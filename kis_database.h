/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __KISDATABASE_H__
#define __KISDATABASE_H__

#include "config.h"

/* Generic data store based on sqlite3 */

#include <memory>
#include <string>

#include <stdio.h>
#include <sqlite3.h>

#include "globalregistry.h"
#include "kis_mutex.h"

/* Kismet Databases
 *
 * Each database is an independent database file, for locking and data integrity
 * simplicity.
 *
 * Each database contains one core table which contains information about
 * the primary module manipulating state, the database version, and the kismet
 * version which last accessed the file.
 *
 * Database versions are monotonically incrementing numbers; a module is
 * expected to detect when the codebase is newer than the database file and
 * perform any upgrades necessary.
 *
 * Providers of database objects must subclass the database and implement an
 * API to abstract the internal SQL commands; callers should not be expected to
 * implement SQL directly.
 *
 */

class kis_database {
    // Subclasses must implement a public builder, typically one which returns a
    // shared pointer instance if the database is a standalone instance; if it is
    // integrated into a poly class it can be built directly via that classes state
    // system
protected:
    // Initialize a database w/ a known module name; opening the database is done with
    // database_open(...)
    kis_database(std::string in_module_name);

public:
    virtual ~kis_database();

    // Open the database file and initialize the KISMET table; if in_path is empty,
    // the database is opened in the local-user settings dir and named according to
    // the module name
    virtual bool database_open(std::string in_path, int in_flags = 0);
    virtual void database_close();

    virtual bool database_valid();

    virtual unsigned int database_get_db_version();

    // Upgrade a database which doesn't match our version
    virtual int database_upgrade_db() = 0;

protected:
    virtual bool database_create_master_table();

    // Force-set db version, to be called after upgrading the db or
    // creating a new db
    virtual bool database_set_db_version(unsigned int in_version);

    // Module name and target version, filled in by subclasses during initialization
    std::string ds_module_name;

    std::string ds_dbfile;

    kis_mutex ds_mutex;

    sqlite3 *db;
};

/* Dynamic database query binder */
class kis_database_binder {
public:
    kis_database_binder() { }

    template<typename T>
    void bind_field(const std::string& in_query, const T& in_value,
            std::function<int (sqlite3_stmt *, int, T)> in_binder) {
        auto b = std::make_shared<binding<T>>(in_query, in_value, in_binder);
        bindings.push_back(b);
    }

    sqlite3_stmt *make_query(sqlite3 *db, std::string base); 

    template<typename T>
    static int bind_numeric(sqlite3_stmt *stmt, int index, const double& value, 
            std::function<int (sqlite3_stmt *, int, T)> binder) {
        return binder(stmt, index, value);
    }

    static int bind_string(sqlite3_stmt *stmt, int index, std::string value) {
        return sqlite3_bind_text(stmt, index, value.data(), value.length(), 0);
    }

    static int bind_blob(sqlite3_stmt *stmt, int index, std::string value) {
        return sqlite3_bind_blob(stmt, index, value.data(), value.length(), 0);
    }

protected:
    class binding_interface {
    public:
        virtual ~binding_interface() { }

        virtual std::string get_query() = 0;
        virtual int bind_query(sqlite3_stmt *, int) = 0;
    };

    template<typename T>
    class binding : public binding_interface {
    public:
        binding(const std::string& in_query, const T& in_value,
                std::function<int (sqlite3_stmt *, int, T)> in_binder) :
            query {in_query},
            value {in_value},
            binder {in_binder} { }
        virtual ~binding() { }

        virtual std::string get_query() override {
            return query;
        }

        virtual int bind_query(sqlite3_stmt *stmt, int pos) override {
            if (binder == nullptr)
                throw std::runtime_error("no sqlite binding function provided");

            if (stmt == nullptr)
                throw std::runtime_error("null sqlite prepared statement provided");

            return binder(stmt, pos, value);
        }
        
        std::string query;
        const T value;
        std::function<int (sqlite3_stmt *, int, T)> binder;
    };

    std::vector<std::shared_ptr<binding_interface>> bindings;

};

#endif



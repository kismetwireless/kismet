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

#include "kis_database.h"
#include "configfile.h"
#include "messagebus.h"
#include "globalregistry.h"
#include "util.h"

kis_database::kis_database(std::string in_module_name) :
        ds_module_name(in_module_name) {
    ds_mutex.set_name(fmt::format("kis_database({})", in_module_name));

    db = NULL;
}

kis_database::~kis_database() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

bool kis_database::database_open(std::string in_file_path, int in_flags) {
    char *sErrMsg = NULL;

    if (in_file_path.length() == 0) {
        std::string config_dir_path_raw = 
            Globalreg::globalreg->kismet_config->fetch_opt("configdir");
        std::string config_dir_path =
            Globalreg::globalreg->kismet_config->expand_log_path(config_dir_path_raw, "", "", 0, 1);

        ds_dbfile = config_dir_path + "/" + ds_module_name + ".db3"; 
    } else {
        ds_dbfile = in_file_path;
    }

    kis_lock_guard<kis_mutex> lk(ds_mutex);

    int r;

    // Always force readwrite/opencreate ... until this bites us
    in_flags |= SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;

    r = sqlite3_open_v2(ds_dbfile.c_str(), &db, in_flags, NULL);

    if (r) {
        _MSG("kis_database unable to open file " + ds_dbfile + ": " +
                std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        db = NULL;
        return false;
    }

    // Do we have a KISMET table?  If not, this is probably a new database.
    bool k_t_exists = false;

    std::string sql = 
        "SELECT name FROM sqlite_master WHERE type='table' AND name='KISMET'";

    // If the callback is called, we've matched a table name, so we exist
    r = sqlite3_exec(db, sql.c_str(), 
            [] (void *aux, int, char **, char **) -> int {
                bool *m = (bool *) aux;
                *m = true;
                return 0;
            }, 
            (void *) &k_t_exists, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("kis_database unable to query for KISMET main table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return false;
    }

    // If the table doesn't exist, build it...
    if (!k_t_exists) {
        // Build the master table
        if (!database_create_master_table())
            return false;
    } else {
        database_load_db_uuid();
    }

    return true;
}

void kis_database::database_load_db_uuid() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    ds_db_uuid = uuid();

    if (db == NULL)
        return;

    sqlite3_stmt *stmt = NULL;

    // Older files have no db_uuid column; failing to prepare is expected there
    if (sqlite3_prepare_v2(db, "SELECT db_uuid FROM KISMET", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        auto l = sqlite3_column_bytes(stmt, 0);

        if (t != NULL && l == 36) {
            uuid u(std::string((const char *) t, l));
            if (!u.error)
                ds_db_uuid = u;
        }
    }

    sqlite3_finalize(stmt);
}

uuid kis_database::database_get_db_uuid() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);
    return ds_db_uuid;
}

void kis_database::database_close() {
    kis_lock_guard<kis_mutex> lk(ds_mutex, "database_close");

    if (db != NULL) {
        sqlite3_close(db);
    }

    db = NULL;
}

bool kis_database::database_create_master_table() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    std::string sql;

    int r;
    char *sErrMsg = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "CREATE TABLE KISMET ("
        "kismet_version TEXT, "
        "db_version INT, "
        "db_module TEXT, "
        "db_uuid TEXT)";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("kis_database unable to create KISMET main table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return false;
    }

    sql = 
        "INSERT INTO KISMET (kismet_version, db_version, db_module, db_uuid) VALUES (?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database unable to generate prepared statement for master table in " +
                ds_dbfile + ": " + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return false;
    }

    auto kversion = fmt::format("{}.{}.{}-{}", 
            Globalreg::globalreg->version_major,
            Globalreg::globalreg->version_minor,
            Globalreg::globalreg->version_tiny,
            Globalreg::globalreg->version_git_rev);

    uuid dbuuid;
    dbuuid.generate_random_uuid();
    auto dbuuid_str = dbuuid.as_string();

    sqlite3_bind_text(stmt, 1, kversion.c_str(), kversion.length(), 0);
    sqlite3_bind_int(stmt, 2, 0);
    sqlite3_bind_text(stmt, 3, ds_module_name.c_str(), ds_module_name.length(), 0);
    sqlite3_bind_text(stmt, 4, dbuuid_str.c_str(), dbuuid_str.length(), SQLITE_TRANSIENT);

    r = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (r != SQLITE_DONE) {
        _MSG("kis_database unable to populate KISMET main table in " + ds_dbfile + ": " +
                std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return false;
    }

    ds_db_uuid = dbuuid;

    return true;
}

bool kis_database::database_valid() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    return (db != NULL);
}

unsigned int kis_database::database_get_db_version() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    if (db == NULL)
        return 0;

    unsigned int v = 0;
    int r;
    char *sErrMsg = NULL;

    std::string sql = 
        "SELECT db_version FROM KISMET";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *ver, int argc, char **data, char **) -> int {
                if (argc != 1) {
                    *((unsigned int *) ver) = 0;
                    return 0;
                }

                if (sscanf(data[0], "%u", (unsigned int *) ver) != 1) {
                    *((unsigned int *) ver) = 0;
                }

                return 0; 
            }, &v, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("kis_database unable to query db_version in" + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return 0;
    }

    return v;
}

bool kis_database::database_set_db_version(unsigned int version) {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    if (db == NULL)
        return 0;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    std::string sql;

    sql = 
        "UPDATE KISMET SET kismet_version = ?, db_version = ?";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database unable to generate prepared statement to update master table in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return false;
    }

    std::string kversion = Globalreg::globalreg->version_major + "." + 
        Globalreg::globalreg->version_minor + "." +
        Globalreg::globalreg->version_tiny;

    sqlite3_bind_text(stmt, 1, kversion.c_str(), kversion.length(), 0);
    sqlite3_bind_int(stmt, 2, version);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return true;
}

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

#include "sqlite3_cpp11.h"

namespace kissqlite3 {

    std::ostream& operator<<(std::ostream& os, const query_element& q) {
        if (q.nested_query.size() > 0) {
            os << "(";

            bool comma = false;
            for (auto f : q.nested_query) {
                os << f;

                // look forward into if it was an op-only token, don't add a comma
                if (f.op_only) {
                    comma = false;
                    continue;
                }

                if (comma)
                    os << ", ";
                comma = true;
            }

            os << ")";

            return os;
        }

        // Output a single operator token and exit
        if (q.op_only) {
            os << q.op;
            return os;
        }

        // output a full query
        os << q.field << " " << q.op << " ?";
        return os;
    }

    std::ostream& operator<<(std::ostream& os, const query& q) {
        os << "SELECT (";

        bool comma = false;
        for (auto f : q.fields) {
            if (comma)
                os << ", ";
            comma = true;

            os << f;
        }
        os << ") FROM " << q.table;

        if (q.where_clause.size() > 0) {
            os << " WHERE ";

            std::function<void (const std::list<query_element>)> cat_clause = 
                [&os, &cat_clause](const std::list<query_element>& e) { 
                    os << "(";

                    bool comma = false;

                    for (auto c : e) {
                        // it'd be nice not to have to look into this like we do
                        // here but it's good enough for now.  We don't want to 
                        // add commas around op-only stanzas

                        if (c.op_only) {
                            if (c.nested_query.size() > 0) {
                                cat_clause(c.nested_query);
                            } else {
                                os << " " << c.op << " ";
                                comma = false;
                            }
                            continue;
                        }

                        if (comma) 
                            os << ", ";
                        comma = true;

                        os << c;
                    }
                    os << ")";

                };

            cat_clause(q.where_clause);
        }

        for (auto c : q.tail_clause) {
            os << " " << c.op;

            if (c.bind_type == BindType::sql_int)
                os << " " << c.num_value;
            else
                os << " " << c.value;
        }

        os << ";" << std::endl;

        if (q.where_clause.size() > 0) {
            std::function<void (unsigned int&, const query_element&)> bind_function = 
                [&bind_function, &os](unsigned int& bind_pos, const query_element& c) {

                    if (c.nested_query.size() > 0) {
                        for (auto nc : c.nested_query) {
                            bind_function(bind_pos, nc);
                        }
                    }

                    if (c.op_only)
                        return;

                    os << "  " << bind_pos++ << " bind_";

                    switch (c.bind_type) {
                        case BindType::sql_blob:
                            os << "blob(\"" << c.value << "\", " << c.value.length() << ")";
                            break;
                        case BindType::sql_text:
                            os << "text(\"" << c.value << "\", " << c.value.length() << ")";
                            break;
                        case BindType::sql_int:
                            os << "int(" << (int) c.num_value << ")";
                            break;
                        case BindType::sql_int64:
                            os << "int64(" << (int64_t) c.num_value << ")";
                            break;
                        case BindType::sql_double:
                            os << "double(" << c.num_value << ")";
                            break;
                        case BindType::sql_null:
                            os << "null(nullptr);";
                            break;
                        case BindType::sql_joining_op:
                            break;
                    };

                    os << std::endl;
                };

            unsigned int bind_pos = 1;
            for (auto c : q.where_clause)
                bind_function(bind_pos, c);
        }

        return os;
    }

    std::list<query_element> _WHERE() {
        auto ret = std::list<query_element>{};
        return ret;
    }

    // SELECT (x, y, z) FROM table
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields) {
        if (fields.size() == 0)
            throw std::runtime_error("invalid SQL query, must have some fields");
        return query{db, table, fields};
    }

    // SELECT (x, y, z) FROM table WHERE (...)
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const std::list<query_element>& where_clause) {
        return query{db, table, fields, where_clause};
    }

    // SELECT (x, y, z) FROM table WHERE (...) LIMIT N
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const std::list<query_element>& where_clause,
            const _LIMIT& lim_op, int limit) {
        return query{db, table, fields, where_clause, {{lim_op, limit}}};
    }

    // SELECT (x, y, z) FROM table WHERE (...) ORDER BY f
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const std::list<query_element>& where_clause,
            const _ORDERBY& ord_op, const std::string& field) {
        return query{db, table, fields, where_clause, {{ord_op, field}}};
    }

    // SELECT (x, y, z) FROM table WHERE (...) ORDER BY f LIMIT n
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const std::list<query_element>& where_clause,
            const _ORDERBY& ord_op, const std::string& field,
            const _LIMIT& lim_op, int limit) {
        return query{db, table, fields, where_clause, 
            {{ord_op, field}, {lim_op, limit}}};
    }

    // SELECT (x, y, z) FROM table LIMIT N
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const _LIMIT& lim_op, int limit) {
        return query{db, table, fields, {}, {{lim_op, limit}}};
    }

    // SELECT (x, y, z) FROM table ORDER BY f
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const _ORDERBY& ord_op, const std::string& field) {
        return query{db, table, fields, {}, {{ord_op, field}}};
    }

    // SELECT (x, y, z) FROM table ORDER BY f LIMIT n
    query _SELECT(sqlite3 *db, const std::string& table, const std::list<std::string>& fields,
            const _ORDERBY& ord_op, const std::string& field,
            const _LIMIT& lim_op, int limit) {
        return query{db, table, fields, {}, 
            {{ord_op, field}, {lim_op, limit}}};
    }

    // DELETE FROM table
    query _DELETE(sqlite3 *db, const std::string& table) {
        return query{db, "DELETE", table, {}};
    }

    // DELETE FROM table WHERE (...)
    query _DELETE(sqlite3 *db, const std::string& table, 
            const std::list<query_element>& where_clause) {
        return query{db, "DELETE", table, {}, where_clause};
    }

    // DELETE FROM table WHERE (...) LIMIT N
    query _DELETE(sqlite3 *db, const std::string& table,
            const std::list<query_element>& where_clause,
            const _LIMIT& lim_op, int limit) {
        return query{db, "DELETE", table, {}, where_clause, {{lim_op, limit}}};
    }

    std::ostream& operator<<(std::ostream& os, const insert& i) {
        os << "INSERT INTO " << i.table << " (";

        bool comma = false;
        for (auto f : i.insert_fields) {
            if (comma)
                os << ", ";
            comma = true;

            os << f;
        }

        os << ") VALUES (";

        comma = false;
        for (auto t : i.insert_terms) {
            if (comma)
                os << ", ";
            comma = true;

            os << "?";
        }

        os << ");" << std::endl;

        for (auto t : i.insert_terms) {
            os << "  bind_";

            switch (t.bind_type) {
                case BindType::sql_blob:
                    os << "blob(\"" << t.value << "\", " << t.value.length() << ")";
                    break;
                case BindType::sql_text:
                    os << "text(\"" << t.value << "\", " << t.value.length() << ")";
                    break;
                case BindType::sql_int:
                    os << "int(" << (int) t.num_value << ")";
                    break;
                case BindType::sql_int64:
                    os << "int64(" << (int64_t) t.num_value << ")";
                    break;
                case BindType::sql_double:
                    os << "double(" << t.num_value << ")";
                    break;
                case BindType::sql_null:
                    os << "null(nullptr);";
                    break;
                case BindType::sql_joining_op:
                    break;
            };

            os << std::endl;
        }

        return os;
    }

    insert _INSERT(const std::string& table, const std::list<std::string>& fields,
            const std::list<insert_elem>& terms) {
        return insert(table, fields, terms);
    }

    std::ostream& operator<<(std::ostream& os, const update& q) {
        os << "UPDATE " << q.table << " SET ";

        bool comma = false;
        for (auto f : q.fields) {
            if (comma)
                os << ", ";
            comma = true;

            os << f << " = ?";
        }

        if (q.where_clause.size() > 0) {
            os << " WHERE (";

            comma = false;
            for (auto c : q.where_clause) {
                if (c.op_only) {
                    os << " " << c.op << " ";
                    comma = false;
                    continue;
                }

                if (comma) 
                    os << ", ";
                comma = true;

                os << c.field << " " << c.op << " ?";
            }
            os << ")";
        }

        os << ";" << std::endl;

        for (auto t : q.terms) {
            os << "  bind_";

            switch (t.bind_type) {
                case BindType::sql_blob:
                    os << "blob(\"" << t.value << "\", " << t.value.length() << ")";
                    break;
                case BindType::sql_text:
                    os << "text(\"" << t.value << "\", " << t.value.length() << ")";
                    break;
                case BindType::sql_int:
                    os << "int(" << (int) t.num_value << ")";
                    break;
                case BindType::sql_int64:
                    os << "int64(" << (int64_t) t.num_value << ")";
                    break;
                case BindType::sql_double:
                    os << "double(" << t.num_value << ")";
                    break;
                case BindType::sql_null:
                    os << "null(nullptr);";
                    break;
                case BindType::sql_joining_op:
                    break;
            };

            os << std::endl;
        }

        if (q.where_clause.size() > 0) {
            for (auto c : q.where_clause) {
                if (c.op_only)
                    continue;

                os << "  bind_";
                
                switch (c.bind_type) {
                    case BindType::sql_blob:
                        os << "blob(\"" << c.value << "\", " << c.value.length() << ")";
                        break;
                    case BindType::sql_text:
                        os << "text(\"" << c.value << "\", " << c.value.length() << ")";
                        break;
                    case BindType::sql_int:
                        os << "int(" << (int) c.num_value << ")";
                        break;
                    case BindType::sql_int64:
                        os << "int64(" << (int64_t) c.num_value << ")";
                        break;
                    case BindType::sql_double:
                        os << "double(" << c.num_value << ")";
                        break;
                    case BindType::sql_null:
                        os << "null(nullptr);";
                        break;
                    case BindType::sql_joining_op:
                        break;
                };

                os << std::endl;
            }
        }
        return os;
    }

    update _UPDATE(const std::string& table, const std::list<std::string>& fields,
            const std::list<insert_elem>& terms) {
        return update(table, fields, terms);
    }

    update _UPDATE(const std::string& table, const std::list<std::string>& fields,
            const std::list<insert_elem>& terms, const std::list<query_element>& where_clause) {
        return update(table, fields, terms, where_clause);
    }

    // Extractors
    template<typename T>
    T sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column);

    template<>
    int sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (int) sqlite3_column_int(stmt.get(), column);
    }

    template<>
    unsigned int sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (unsigned int) sqlite3_column_int(stmt.get(), column);
    }

    template<>
    long sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (long) sqlite3_column_int64(stmt.get(), column);
    }

    template<>
    unsigned long sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (unsigned long) sqlite3_column_int64(stmt.get(), column);
    }

    template<>
    long long sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (long long) sqlite3_column_int64(stmt.get(), column);
    }

    template<>
    unsigned long long sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (unsigned long long) sqlite3_column_int64(stmt.get(), column);
    }

    template<>
    bool sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (bool) sqlite3_column_int(stmt.get(), column);
    }

    template<>
    float sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return (float) sqlite3_column_double(stmt.get(), column);
    }

    template<>
    double sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        return sqlite3_column_double(stmt.get(), column);
    }

    template<>
    std::string sqlite3_column_as(std::shared_ptr<sqlite3_stmt> stmt, unsigned int column) {
        auto raw = (const char *) sqlite3_column_blob(stmt.get(), column);
        auto len = sqlite3_column_bytes(stmt.get(), column);
        return std::string(raw, len);
    }

};


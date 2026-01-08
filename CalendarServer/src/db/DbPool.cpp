#include "DbPool.h"
#include <stdexcept>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include "../observability/Logging.h"
#include <vector>

namespace db {


static void post_db_result(boost::asio::io_context& ioc, DbResultCb cb, boost::system::error_code ec, DbResult&& r) {
    
    ioc.post([cb, ec, r = std::move(r)]() mutable {
        cb(ec, std::move(r));
    });
}



static std::optional<std::string> build_pg_timestamptz_array(const std::vector<std::string>& vals) {
    if (vals.empty()) return std::optional<std::string>(std::string("{}"));
    std::string out = "{";
    for (size_t i = 0; i < vals.size(); ++i) {
        if (i) out += ",";
        const std::string& v = vals[i];
        if (v.find('\"') != std::string::npos || v.find('\\') != std::string::npos) return std::nullopt;
        if (v.empty()) {
            // represent NULL element in array literal
            out += "NULL";
        } else {
            out += '"';
            out += v;
            out += '"';
        }
    }
    out += "}";
    return out;
}

struct DbPool::Impl {
    boost::asio::io_context& app_ioc;
    std::string conninfo;
    int workers = 2;

    struct Task { std::function<void(PGconn*&)> fn; };
    std::queue<Task> tasks;
    std::mutex mu_tasks;
    std::condition_variable cv_tasks;
    bool stopping = false;

    std::vector<std::thread> threads;

    Impl(boost::asio::io_context& ioc, const std::string& ci, int workers_)
        : app_ioc(ioc), conninfo(ci), workers(workers_) {
        for (int i = 0; i < workers; ++i) threads.emplace_back([this]{ this->worker_loop(); });
    }

    ~Impl() {
        { std::lock_guard<std::mutex> lk(mu_tasks); stopping = true; }
        cv_tasks.notify_all();
        for (auto &t : threads) if (t.joinable()) t.join();
    }

    PGconn* connect_one() {
        PGconn* c = PQconnectdb(conninfo.c_str());
        if (c == nullptr) return nullptr;
        if (PQstatus(c) != CONNECTION_OK) {
            PQfinish(c);
            return nullptr;
        }
        return c;
    }

    void worker_loop() {
        PGconn* local_conn = nullptr;
    local_conn = connect_one();
    observability::log_info("dbpool.worker_started", {{"local_conn", local_conn ? std::string("ok") : std::string("null")}});
        while (true) {
            Task task;
            {
                std::unique_lock<std::mutex> lk(mu_tasks);
                cv_tasks.wait(lk, [this]{ return stopping || !tasks.empty(); });
                if (stopping && tasks.empty()) {
                    if (local_conn) { PQfinish(local_conn); local_conn = nullptr; }
                    return;
                }
                task = std::move(tasks.front()); tasks.pop();
            }
#ifdef DBPOOL_DEBUG
            observability::log_info("dbpool.worker_exec", {{"local_conn", local_conn ? std::string("ok") : std::string("null")}});
#endif
            try {
                task.fn(local_conn);
            } catch (const std::exception& e) {
                observability::log_error(std::string("db task exception: ") + e.what());
            }
        }
    }

    void post_task(std::function<void(PGconn*&)> f) {
#ifdef DBPOOL_DEBUG
        size_t qsize = 0;
        {
            std::lock_guard<std::mutex> lk(mu_tasks);
            tasks.push(Task{f});
            qsize = tasks.size();
        }
        observability::log_info("dbpool.post_task", {{"queue_size", int64_t(qsize)}});
        cv_tasks.notify_one();
#else
        {
            std::lock_guard<std::mutex> lk(mu_tasks);
            tasks.push(Task{f});
        }
        cv_tasks.notify_one();
#endif
    }
};

DbPool::DbPool(boost::asio::io_context& app_ioc, const std::string& conninfo, int workers) {
    impl_ = std::make_unique<Impl>(app_ioc, conninfo, workers);
}

DbPool::~DbPool() = default;

// Legacy low-level implementation that exposes PGresult via ResultPtr
void DbPool::async_exec_legacy(const std::string& sql, DbCallback cb) {
    auto impl = impl_.get();
    impl->post_task([impl, sql, cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec;
        PGresult* r = nullptr;
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!local_conn) {
                local_conn = impl->connect_one();
                if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); break; }
            }
            r = PQexec(local_conn, sql.c_str());
            if (!r) { PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); continue; }
            break;
        }
        ResultPtr rp;
        if (r) rp = ResultPtr(r, [](PGresult* p){ PQclear(p); });
        if (r) {
            ExecStatusType st = PQresultStatus(r);
            if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
                observability::log_warn("dbpool.exec_result_non_ok", {{"status", std::string(PQresStatus(st))}, {"msg", std::string(PQresultErrorMessage(r) ? PQresultErrorMessage(r) : "")}});
            }
        } else {
            observability::log_warn("dbpool.exec_null", {{"err", ec.message()}});
        }
    impl->app_ioc.post([cb, ec, rp]() mutable { cb(ec, rp); });
    });
}

// Legacy low-level implementation that exposes PGresult via ResultPtr
void DbPool::async_exec_params_legacy(const std::string& sql, std::vector<std::string> params, DbCallback cb) {
    auto impl = impl_.get();
    impl->post_task([impl, sql, params = std::move(params), cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec;
        PGresult* r = nullptr;
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!local_conn) {
                local_conn = impl->connect_one();
                if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); break; }
            }
            std::vector<const char*> cparams; cparams.reserve(params.size());
            for (const auto& p : params) cparams.push_back(p.c_str());
            r = PQexecParams(local_conn, sql.c_str(), int(cparams.size()), nullptr, cparams.data(), nullptr, nullptr, 0);
            if (!r) { PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); continue; }
            break;
        }
        ResultPtr rp;
        if (r) rp = ResultPtr(r, [](PGresult* p){ PQclear(p); });
        if (r) {
            ExecStatusType st = PQresultStatus(r);
            if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
                observability::log_warn("dbpool.exec_params_non_ok", {{"status", std::string(PQresStatus(st))}, {"msg", std::string(PQresultErrorMessage(r) ? PQresultErrorMessage(r) : "")}});
            }
        } else {
            observability::log_warn("dbpool.exec_params_null", {{"err", ec.message()}});
        }
    impl->app_ioc.post([cb, ec, rp]() mutable { cb(ec, rp); });
    });
}

// New public API: parse PGresult into DbResult and deliver to caller
void DbPool::async_exec(const std::string& sql, DbResultCb cb) {
    // call legacy and convert
    async_exec_legacy(sql, [cb](const boost::system::error_code& ec, ResultPtr rp) {
        DbResult r;
        if (rp) {
            PGresult* pr = rp.get();
            ExecStatusType st = PQresultStatus(pr);
            r.ok = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
            const char* ss = PQresultErrorField(pr, PG_DIAG_SQLSTATE);
            r.sqlstate = ss ? ss : std::string();
            const char* msg = PQresultErrorMessage(pr);
            r.message = msg ? msg : std::string();
            int nfields = PQnfields(pr);
            for (int i = 0; i < nfields; ++i) r.columns.emplace_back(PQfname(pr, i) ? PQfname(pr, i) : "");
            int ntuples = PQntuples(pr);
            r.rows.reserve(ntuples);
            for (int i = 0; i < ntuples; ++i) {
                std::vector<std::optional<std::string>> row; row.reserve(nfields);
                for (int j = 0; j < nfields; ++j) {
                    if (PQgetisnull(pr, i, j)) {
                        row.emplace_back(std::nullopt);
                    } else {
                        char* v = PQgetvalue(pr, i, j);
                        row.emplace_back(v ? std::optional<std::string>(std::string(v)) : std::nullopt);
                    }
                }
                // optional diagnostic: log first column length to detect corruption at INFO level
                try {
#ifdef DBPOOL_DEBUG
                    if (!row.empty() && row[0].has_value()) observability::log_info("dbpool.row_len", {{"len", int64_t(row[0]->size())}});
#endif
                } catch(...) { observability::log_warn("dbpool.row_logging_failed", {}); }
                r.rows.emplace_back(std::move(row));
            }
            if (st == PGRES_COMMAND_OK) {
                char* ct = PQcmdTuples(pr);
                r.affected_rows = ct ? atoi(ct) : 0;
            } else {
                r.affected_rows = ntuples;
            }
        }
        cb(ec, std::move(r));
    });
}

void DbPool::async_exec_params(const std::string& sql, std::vector<std::string> params, DbResultCb cb) {
    async_exec_params_legacy(sql, std::move(params), [cb](const boost::system::error_code& ec, ResultPtr rp) {
        DbResult r;
        if (rp) {
            PGresult* pr = rp.get();
            ExecStatusType st = PQresultStatus(pr);
            r.ok = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
            const char* ss = PQresultErrorField(pr, PG_DIAG_SQLSTATE);
            r.sqlstate = ss ? ss : std::string();
            const char* msg = PQresultErrorMessage(pr);
            r.message = msg ? msg : std::string();
            int nfields = PQnfields(pr);
            for (int i = 0; i < nfields; ++i) r.columns.emplace_back(PQfname(pr, i) ? PQfname(pr, i) : "");
            int ntuples = PQntuples(pr);
            r.rows.reserve(ntuples);
            for (int i = 0; i < ntuples; ++i) {
                std::vector<std::optional<std::string>> row; row.reserve(nfields);
                for (int j = 0; j < nfields; ++j) {
                    if (PQgetisnull(pr, i, j)) {
                        row.emplace_back(std::nullopt);
                    } else {
                        char* v = PQgetvalue(pr, i, j);
                        row.emplace_back(v ? std::optional<std::string>(std::string(v)) : std::nullopt);
                    }
                }
                r.rows.emplace_back(std::move(row));
            }
            if (st == PGRES_COMMAND_OK) {
                char* ct = PQcmdTuples(pr);
                r.affected_rows = ct ? atoi(ct) : 0;
            } else {
                r.affected_rows = ntuples;
            }
        }
        cb(ec, std::move(r));
    });
}

void DbPool::async_scalar_int(const std::string& sql, ScalarIntCb cb) {
    async_exec(sql, [cb](const boost::system::error_code& ec, const DbResult& r) {
        if (ec) { cb(ec, 0); return; }
        if (!r.ok || r.rows.empty() || r.rows[0].empty()) { cb(boost::asio::error::operation_aborted, 0); return; }
        try { 
            if (!r.rows.empty() && !r.rows[0].empty() && r.rows[0][0].has_value()) {
                int val = std::stoi(r.rows[0][0].value()); cb({}, val);
            } else cb(boost::asio::error::invalid_argument, 0);
        } catch(...) { cb(boost::asio::error::invalid_argument, 0); }
    });
}

void DbPool::async_insert_user(const std::string& email, const std::string& password_hash, DbResultCb cb) {
    const std::string sql = "INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id";
    async_exec_params(sql, std::vector<std::string>{email, password_hash}, cb);
}

void DbPool::async_get_user_by_email(const std::string& email, DbResultCb cb) {
    const std::string sql = "SELECT id, email, password_hash FROM users WHERE email=$1 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{email}, cb);
}

void DbPool::async_get_user_by_id(const std::string& id, DbResultCb cb) {
    const std::string sql = "SELECT id, email, password_hash FROM users WHERE id=$1 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{id}, cb);
}

void DbPool::async_create_calendar(std::string owner_id, std::string title, DbResultCb cb) {
    // perform transaction: insert calendar and insert owner membership role=2
    auto impl = impl_.get();
    impl->post_task([impl, owner_id = std::move(owner_id), title = std::move(title), cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec;
        DbResult r;
    if (!local_conn) local_conn = impl->connect_one();
    if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PGresult* res = PQexec(local_conn, "BEGIN");
    if (!res) { PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        const char* sql1 = "INSERT INTO calendars(title, owner_user_id) VALUES($1, $2) RETURNING id";
        const char* params1[2] = { title.c_str(), owner_id.c_str() };
        res = PQexecParams(local_conn, sql1, 2, nullptr, params1, nullptr, nullptr, 0);
    if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            std::string msg = PQresultErrorMessage(res);
            PQclear(res);
            PQexec(local_conn, "ROLLBACK");
            r.ok = false; r.message = msg;
            post_db_result(impl->app_ioc, cb, ec, std::move(r));
            return;
        }
        char* cal_id = PQgetvalue(res, 0, 0);
        // no raw pointer logging in production
        std::string calendar_id = cal_id ? cal_id : std::string();
        PQclear(res);
        // insert membership owner role=2
        const char* sql2 = "INSERT INTO calendar_memberships(calendar_id, user_id, role) VALUES($1, $2, $3)";
        std::string role_str = std::to_string(2);
        const char* params2[3] = { calendar_id.c_str(), owner_id.c_str(), role_str.c_str() };
        res = PQexecParams(local_conn, sql2, 3, nullptr, params2, nullptr, nullptr, 0);
    if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            std::string msg = PQresultErrorMessage(res);
            PQclear(res);
            PQexec(local_conn, "ROLLBACK");
            r.ok = false; r.message = msg;
            post_db_result(impl->app_ioc, cb, ec, std::move(r));
            return;
        }
        PQclear(res);
        res = PQexec(local_conn, "COMMIT");
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
            if (res) PQclear(res);
            PQexec(local_conn, "ROLLBACK");
            r.ok = false; r.message = "commit failed";
            post_db_result(impl->app_ioc, cb, ec, std::move(r));
            return;
        }
        PQclear(res);
    r.ok = true;
    // push a single-row result containing the calendar id
    r.rows.emplace_back();
    r.rows.back().emplace_back(calendar_id);
    try {
#ifdef DBPOOL_DEBUG
        observability::log_info("dbpool.create_calendar", {{"calendar_id_len", int64_t(calendar_id.size())}});
#endif
    } catch(...) {}
    post_db_result(impl->app_ioc, cb, ec, std::move(r));
    });
}

void DbPool::async_list_calendars_for_user(std::string user_id, DbResultCb cb) {
    // include membership role as the 4th column
    const std::string sql = "SELECT c.id, c.title, c.owner_user_id, m.role FROM calendars c JOIN calendar_memberships m ON m.calendar_id=c.id WHERE m.user_id=$1";
    async_exec_params(sql, std::vector<std::string>{std::move(user_id)}, cb);
}

void DbPool::async_get_calendar(std::string calendar_id, DbResultCb cb) {
    const std::string sql = "SELECT id, title, owner_user_id, created_at FROM calendars WHERE id=$1 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id)}, cb);
}

void DbPool::async_add_membership(std::string calendar_id, std::string user_id, int role, DbResultCb cb) {
    const std::string sql = "INSERT INTO calendar_memberships(calendar_id, user_id, role) VALUES($1, $2, $3)";
    // Diagnostic logging to help track any unexpected large allocations
    try {
#ifdef DBPOOL_DEBUG
        observability::log_info("dbpool.add_membership", {{"calendar_id_len", int64_t(calendar_id.size())}, {"user_id_len", int64_t(user_id.size())}, {"role", int64_t(role)}});
#endif
    } catch(...) {}
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id), std::move(user_id), std::to_string(role)}, cb);
}

void DbPool::async_get_membership(std::string calendar_id, std::string user_id, DbResultCb cb) {
    const std::string sql = "SELECT m.calendar_id, m.user_id, m.role, u.email FROM calendar_memberships m JOIN users u ON u.id = m.user_id WHERE m.calendar_id=$1 AND m.user_id=$2 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id), std::move(user_id)}, cb);
}

void DbPool::async_list_memberships(std::string calendar_id, DbResultCb cb) {
    const std::string sql = "SELECT m.user_id, u.email, m.role, m.created_at FROM calendar_memberships m JOIN users u ON u.id = m.user_id WHERE m.calendar_id=$1";
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id)}, cb);
}

void DbPool::async_update_membership_role(std::string calendar_id, std::string user_id, int role, DbResultCb cb) {
    const std::string sql = "UPDATE calendar_memberships SET role=$3 WHERE calendar_id=$1 AND user_id=$2";
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id), std::move(user_id), std::to_string(role)}, cb);
}

void DbPool::async_remove_membership(std::string calendar_id, std::string user_id, DbResultCb cb) {
    const std::string sql = "DELETE FROM calendar_memberships WHERE calendar_id=$1 AND user_id=$2";
    async_exec_params(sql, std::vector<std::string>{std::move(calendar_id), std::move(user_id)}, cb);
}

// Events
void DbPool::async_create_event(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb) {
    const std::string sql = "INSERT INTO events(calendar_id, created_by, title, description, start_ts, end_ts) VALUES($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,'')::timestamptz) RETURNING id, calendar_id, title, description, start_ts, end_ts, created_by, created_at, updated_at";
    std::vector<std::string> params;
    params.push_back(calendar_id);
    params.push_back(created_by);
    params.push_back(title);
    params.push_back(description.has_value() ? description.value() : std::string());
    params.push_back(start_ts);
    params.push_back(end_ts.has_value() ? end_ts.value() : std::string());
    async_exec_params(sql, std::move(params), cb);
}

// Atomic create: event + single occurrence in one transaction
void DbPool::async_create_event_with_occurrence(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb) {
    auto impl = impl_.get();
    impl->post_task([impl, calendar_id = std::move(calendar_id), created_by = std::move(created_by), title = std::move(title), description, start_ts = std::move(start_ts), end_ts, cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec;
        DbResult r;
        if (!local_conn) local_conn = impl->connect_one();
        if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PGresult* res = PQexec(local_conn, "BEGIN");
        if (!res) { PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        const char* sql1 = "INSERT INTO events(calendar_id, created_by, title, description, start_ts, end_ts) VALUES($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,'')::timestamptz) RETURNING id, calendar_id, title, description, start_ts, end_ts, created_by, created_at, updated_at";
        std::string desc = description.has_value() ? description.value() : std::string();
        const char* params1[6] = { calendar_id.c_str(), created_by.c_str(), title.c_str(), desc.c_str(), start_ts.c_str(), end_ts.has_value() ? end_ts->c_str() : "" };
        res = PQexecParams(local_conn, sql1, 6, nullptr, params1, nullptr, nullptr, 0);
        if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_TUPLES_OK) { std::string msg = PQresultErrorMessage(res); PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = msg; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        // extract full returned row into DbResult
        int nfields = PQnfields(res);
        int ntuples = PQntuples(res);
        if (ntuples >= 1) {
            r.rows.emplace_back();
            for (int j = 0; j < nfields; ++j) {
                if (PQgetisnull(res, 0, j)) r.rows.back().emplace_back(std::nullopt);
                else r.rows.back().emplace_back(std::string(PQgetvalue(res, 0, j)));
            }
        }
        // keep event_id for internal use
        char* ev_id = PQgetvalue(res, 0, 0);
        std::string event_id = ev_id ? ev_id : std::string();
        PQclear(res);
        // Use text[] + NULLIF(e,'')::timestamptz in SQL to avoid invalid empty-string->timestamptz casts
        const char* sql_ins = "INSERT INTO occurrences(event_id, start_ts, end_ts, created_at) SELECT $1, s::timestamptz, NULLIF(e,'')::timestamptz, now() FROM UNNEST($2::text[], $3::text[]) AS t(s, e) ON CONFLICT (event_id, start_ts) DO NOTHING";
        // Build timestamptz[] array literals for starts and ends
    std::vector<std::string> starts_v; starts_v.push_back(start_ts);
    std::vector<std::string> ends_v;
    // ensure arrays have matching lengths; represent missing end_ts as empty string
    ends_v.push_back(end_ts.has_value() ? *end_ts : std::string());
    // defensive: ensure lengths match (they do here), but keep check for future edits
    if (starts_v.size() != ends_v.size()) {
        r.ok = false; r.message = "mismatched start/end arrays"; PQexec(local_conn, "ROLLBACK"); post_db_result(impl->app_ioc, cb, boost::asio::error::invalid_argument, std::move(r)); return;
    }
        auto starts_arr_opt = build_pg_timestamptz_array(starts_v);
        auto ends_arr_opt = build_pg_timestamptz_array(ends_v);
        if (!starts_arr_opt.has_value() || !ends_arr_opt.has_value()) {
            // invalid characters found in timestamps -> treat as bad request at higher layer; return error here
            r.ok = false; r.message = "invalid timestamp values for array"; PQexec(local_conn, "ROLLBACK"); post_db_result(impl->app_ioc, cb, boost::asio::error::invalid_argument, std::move(r)); return;
        }
        std::string starts = *starts_arr_opt;
        std::string ends = *ends_arr_opt;
        // ensure params live until PQexecParams returns
        const char* params2[3] = { event_id.c_str(), starts.c_str(), ends.c_str() };
        res = PQexecParams(local_conn, sql_ins, 3, nullptr, params2, nullptr, nullptr, 0);
        if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) { std::string msg = PQresultErrorMessage(res); PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = msg; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        res = PQexec(local_conn, "COMMIT");
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) { if (res) PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = "commit failed"; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
    r.ok = true;
    post_db_result(impl->app_ioc, cb, ec, std::move(r));
    });
}

// Atomic create event + recurrence rule + bulk insert of occurrences
void DbPool::async_create_event_with_recurrence(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, const std::string& freq, int interval, const std::optional<int>& count, const std::optional<std::string>& until_ts, const std::optional<std::vector<int>>& byweekday, const std::vector<std::string>& occ_starts, const std::vector<std::string>& occ_ends, DbResultCb cb) {
    auto impl = impl_.get();
    impl->post_task([impl, calendar_id = std::move(calendar_id), created_by = std::move(created_by), title = std::move(title), description, start_ts = std::move(start_ts), end_ts, freq = std::move(freq), interval, count, until_ts, byweekday, occ_starts, occ_ends, cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec;
        DbResult r;
        if (!local_conn) local_conn = impl->connect_one();
        if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PGresult* res = PQexec(local_conn, "BEGIN");
        if (!res) { PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        const char* sql1 = "INSERT INTO events(calendar_id, created_by, title, description, start_ts, end_ts) VALUES($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,'')::timestamptz) RETURNING id, calendar_id, title, description, start_ts, end_ts, created_by, created_at, updated_at";
        std::string desc = description.has_value() ? description.value() : std::string();
        const char* params1[6] = { calendar_id.c_str(), created_by.c_str(), title.c_str(), desc.c_str(), start_ts.c_str(), end_ts.has_value() ? end_ts->c_str() : "" };
        res = PQexecParams(local_conn, sql1, 6, nullptr, params1, nullptr, nullptr, 0);
        if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_TUPLES_OK) { std::string msg = PQresultErrorMessage(res); PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = msg; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        int nfields = PQnfields(res);
        int ntuples = PQntuples(res);
        if (ntuples >= 1) {
            r.rows.emplace_back();
            for (int j = 0; j < nfields; ++j) {
                if (PQgetisnull(res, 0, j)) r.rows.back().emplace_back(std::nullopt);
                else r.rows.back().emplace_back(std::string(PQgetvalue(res, 0, j)));
            }
        }
        char* ev_id = PQgetvalue(res, 0, 0);
        std::string event_id = ev_id ? ev_id : std::string();
        PQclear(res);
        const char* sql_rule = "INSERT INTO recurrence_rules(event_id, freq, interval, count, until_ts, byweekday) VALUES($1,$2,$3, NULLIF($4,'')::int, NULLIF($5,'')::timestamptz, NULLIF($6,'')::int[])";
        std::string bywd = "";
        if (byweekday.has_value() && !byweekday->empty()) {
            std::string tmp = "{";
            for (size_t i=0;i<byweekday->size();++i) { if (i) tmp += ","; tmp += std::to_string((*byweekday)[i]); }
            tmp += "}";
            bywd = tmp;
        }
        std::string count_s = count.has_value() ? std::to_string(count.value()) : std::string();
    // avoid temporary c_str() on temporary std::to_string() — keep a stable string
    std::string interval_s = std::to_string(interval);
    const char* params_rule[6] = { event_id.c_str(), freq.c_str(), interval_s.c_str(), count_s.c_str(), until_ts.has_value() ? until_ts->c_str() : "", bywd.empty() ? "" : bywd.c_str() };
        res = PQexecParams(local_conn, sql_rule, 6, nullptr, params_rule, nullptr, nullptr, 0);
        if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) { std::string msg = PQresultErrorMessage(res); PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = msg; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        // use text[] literals and cast to timestamptz to avoid unsafe direct timestamptz[] literal building
        const char* sql_ins = "INSERT INTO occurrences(event_id, start_ts, end_ts, created_at) SELECT $1, t.start_ts::timestamptz, NULLIF(t.end_ts,'')::timestamptz, now() FROM UNNEST($2::text[], $3::text[]) AS t(start_ts, end_ts) ON CONFLICT (event_id, start_ts) DO NOTHING";
        // Ensure occ_ends matches occ_starts in length by padding with empty strings if needed
        std::vector<std::string> safe_occ_starts = occ_starts;
        std::vector<std::string> safe_occ_ends = occ_ends;
        if (safe_occ_ends.size() < safe_occ_starts.size()) {
            safe_occ_ends.resize(safe_occ_starts.size(), std::string());
        }
        if (safe_occ_starts.size() != safe_occ_ends.size()) {
            r.ok = false; r.message = "mismatched occurrence arrays"; PQexec(local_conn, "ROLLBACK"); post_db_result(impl->app_ioc, cb, boost::asio::error::invalid_argument, std::move(r)); return;
        }
        auto starts_opt = build_pg_timestamptz_array(safe_occ_starts);
        auto ends_opt = build_pg_timestamptz_array(safe_occ_ends);
        if (!starts_opt.has_value() || !ends_opt.has_value()) {
            r.ok = false; r.message = "invalid timestamp values for array"; PQexec(local_conn, "ROLLBACK"); post_db_result(impl->app_ioc, cb, boost::asio::error::invalid_argument, std::move(r)); return;
        }
        std::string starts = *starts_opt;
        std::string ends = *ends_opt;
        const char* params_ins[3] = { event_id.c_str(), starts.c_str(), ends.c_str() };
        res = PQexecParams(local_conn, sql_ins, 3, nullptr, params_ins, nullptr, nullptr, 0);
        if (!res) { PQexec(local_conn, "ROLLBACK"); PQfinish(local_conn); local_conn = nullptr; ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) { std::string msg = PQresultErrorMessage(res); PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = msg; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
        res = PQexec(local_conn, "COMMIT");
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) { if (res) PQclear(res); PQexec(local_conn, "ROLLBACK"); r.ok = false; r.message = "commit failed"; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        PQclear(res);
    r.ok = true;
    post_db_result(impl->app_ioc, cb, ec, std::move(r));
    });
}

void DbPool::async_list_events(const std::string& calendar_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb) {
    const std::string sql = "SELECT id, title, description, start_ts, end_ts, created_by, created_at, updated_at FROM events WHERE calendar_id=$1 AND start_ts >= $2 AND start_ts < $3 ORDER BY start_ts ASC";
    async_exec_params(sql, std::vector<std::string>{calendar_id, from_ts, to_ts}, cb);
}

void DbPool::async_get_event(const std::string& calendar_id, const std::string& event_id, DbResultCb cb) {
    const std::string sql = "SELECT id, calendar_id, title, description, start_ts, end_ts, created_by, created_at, updated_at FROM events WHERE calendar_id=$1 AND id=$2 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{calendar_id, event_id}, cb);
}

void DbPool::async_update_event_full(const std::string& calendar_id, const std::string& event_id, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb) {
    const std::string sql = "UPDATE events SET title=$3, description=NULLIF($4,''), start_ts=$5, end_ts=NULLIF($6,'')::timestamptz, updated_at=now() WHERE calendar_id=$1 AND id=$2 RETURNING id, calendar_id, title, description, start_ts, end_ts, created_by, created_at, updated_at";
    std::vector<std::string> params;
    params.push_back(calendar_id);
    params.push_back(event_id);
    params.push_back(title);
    params.push_back(description.has_value() ? description.value() : std::string());
    params.push_back(start_ts);
    params.push_back(end_ts.has_value() ? end_ts.value() : std::string());
    async_exec_params(sql, std::move(params), cb);
}

void DbPool::async_delete_event(const std::string& calendar_id, const std::string& event_id, DbResultCb cb) {
    const std::string sql = "DELETE FROM events WHERE calendar_id=$1 AND id=$2";
    async_exec_params(sql, std::vector<std::string>{calendar_id, event_id}, cb);
}

// Tasks
void DbPool::async_create_task(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::optional<std::string>& due_ts, DbResultCb cb) {
    const std::string sql = "INSERT INTO tasks(calendar_id, created_by, title, description, due_ts) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,'')::timestamptz) RETURNING id, calendar_id, title, description, due_ts, status, created_by, created_at, updated_at";
    std::vector<std::string> params;
    params.push_back(calendar_id);
    params.push_back(created_by);
    params.push_back(title);
    params.push_back(description.has_value() ? description.value() : std::string());
    params.push_back(due_ts.has_value() ? due_ts.value() : std::string());
    async_exec_params(sql, std::move(params), cb);
}

void DbPool::async_list_tasks(const std::string& calendar_id, const std::optional<std::string>& from_ts, const std::optional<std::string>& to_ts, const std::optional<int>& status, DbResultCb cb) {
    // choose SQL based on provided filters (no dynamic SQL builder to keep simple)
    if (status.has_value() && from_ts.has_value() && to_ts.has_value()) {
        const std::string sql = "SELECT id, title, description, due_ts, status, created_by, created_at, updated_at FROM tasks WHERE calendar_id=$1 AND due_ts >= $2 AND due_ts < $3 AND status=$4 ORDER BY due_ts ASC NULLS LAST";
        async_exec_params(sql, std::vector<std::string>{calendar_id, from_ts.value(), to_ts.value(), std::to_string(status.value())}, cb);
        return;
    }
    if (from_ts.has_value() && to_ts.has_value()) {
        const std::string sql = "SELECT id, title, description, due_ts, status, created_by, created_at, updated_at FROM tasks WHERE calendar_id=$1 AND due_ts >= $2 AND due_ts < $3 ORDER BY due_ts ASC NULLS LAST";
        async_exec_params(sql, std::vector<std::string>{calendar_id, from_ts.value(), to_ts.value()}, cb);
        return;
    }
    if (status.has_value()) {
        const std::string sql = "SELECT id, title, description, due_ts, status, created_by, created_at, updated_at FROM tasks WHERE calendar_id=$1 AND status=$2 ORDER BY created_at DESC";
        async_exec_params(sql, std::vector<std::string>{calendar_id, std::to_string(status.value())}, cb);
        return;
    }
    const std::string sql = "SELECT id, title, description, due_ts, status, created_by, created_at, updated_at FROM tasks WHERE calendar_id=$1 ORDER BY created_at DESC";
    async_exec_params(sql, std::vector<std::string>{calendar_id}, cb);
}

void DbPool::async_get_task(const std::string& calendar_id, const std::string& task_id, DbResultCb cb) {
    const std::string sql = "SELECT id, calendar_id, title, description, due_ts, status, created_by, created_at, updated_at FROM tasks WHERE calendar_id=$1 AND id=$2 LIMIT 1";
    async_exec_params(sql, std::vector<std::string>{calendar_id, task_id}, cb);
}

void DbPool::async_update_task_full(const std::string& calendar_id, const std::string& task_id, const std::string& title, const std::optional<std::string>& description, const std::optional<std::string>& due_ts, int status, DbResultCb cb) {
    const std::string sql = "UPDATE tasks SET title=$3, description=NULLIF($4,''), due_ts=NULLIF($5,'')::timestamptz, status=$6, updated_at=now() WHERE calendar_id=$1 AND id=$2 RETURNING id, calendar_id, title, description, due_ts, status, created_by, created_at, updated_at";
    std::vector<std::string> params;
    params.push_back(calendar_id);
    params.push_back(task_id);
    params.push_back(title);
    params.push_back(description.has_value() ? description.value() : std::string());
    params.push_back(due_ts.has_value() ? due_ts.value() : std::string());
    params.push_back(std::to_string(status));
    async_exec_params(sql, std::move(params), cb);
}

void DbPool::async_delete_task(const std::string& calendar_id, const std::string& task_id, DbResultCb cb) {
    const std::string sql = "DELETE FROM tasks WHERE calendar_id=$1 AND id=$2";
    async_exec_params(sql, std::vector<std::string>{calendar_id, task_id}, cb);
}

// Recurrence helper implementations
void DbPool::async_create_recurrence_rule(const std::string& event_id, const std::string& freq, int interval, const std::optional<int>& count, const std::optional<std::string>& until_ts, const std::optional<std::vector<int>>& byweekday, DbResultCb cb) {
    const std::string sql = "INSERT INTO recurrence_rules(event_id, freq, interval, count, until_ts, byweekday) VALUES($1,$2,$3::int, NULLIF($4,'')::int, NULLIF($5,'')::timestamptz, NULLIF($6,'')::int[]) RETURNING id";
    std::vector<std::string> params;
    params.push_back(event_id);
    params.push_back(freq);
    params.push_back(std::to_string(interval));
    params.push_back(count.has_value() ? std::to_string(count.value()) : std::string());
    params.push_back(until_ts.has_value() ? until_ts.value() : std::string());
    // byweekday as text representation of array or empty -> pass as string like '{1,3}'
    if (byweekday.has_value() && !byweekday->empty()) {
        std::string arr = "{";
        for (size_t i=0;i<byweekday->size();++i) { if (i) arr += ","; arr += std::to_string((*byweekday)[i]); }
        arr += "}";
        params.push_back(arr);
    } else params.push_back(std::string());
    async_exec_params(sql, std::move(params), cb);
}

void DbPool::async_add_recurrence_exdate(const std::string& rule_id, const std::string& exdate, DbResultCb cb) {
    const std::string sql = "INSERT INTO recurrence_exdates(rule_id, exdate) VALUES($1, $2) ON CONFLICT DO NOTHING";
    async_exec_params(sql, std::vector<std::string>{rule_id, exdate}, cb);
}

void DbPool::async_remove_recurrence_exdate(const std::string& rule_id, const std::string& exdate, DbResultCb cb) {
    const std::string sql = "DELETE FROM recurrence_exdates WHERE rule_id=$1 AND exdate=$2";
    async_exec_params(sql, std::vector<std::string>{rule_id, exdate}, cb);
}

void DbPool::async_upsert_occurrence_override(const std::string& rule_id, const std::string& original_start_ts, const std::optional<std::string>& new_start_ts, const std::optional<std::string>& new_end_ts, const std::optional<std::string>& title, const std::optional<std::string>& notes, bool cancelled, DbResultCb cb) {
    // Upsert based on UNIQUE(rule_id, original_start_ts)
    const std::string sql = "INSERT INTO occurrence_overrides(rule_id, original_start_ts, new_start_ts, new_end_ts, title, notes, is_cancelled, updated_at) VALUES($1,$2,NULLIF($3,'')::timestamptz, NULLIF($4,'')::timestamptz, NULLIF($5,''), NULLIF($6,''), $7, now()) ON CONFLICT (rule_id, original_start_ts) DO UPDATE SET new_start_ts=EXCLUDED.new_start_ts, new_end_ts=EXCLUDED.new_end_ts, title=EXCLUDED.title, notes=EXCLUDED.notes, is_cancelled=EXCLUDED.is_cancelled, updated_at=now()";
    std::vector<std::string> params;
    params.push_back(rule_id);
    params.push_back(original_start_ts);
    params.push_back(new_start_ts.has_value() ? new_start_ts.value() : std::string());
    params.push_back(new_end_ts.has_value() ? new_end_ts.value() : std::string());
    params.push_back(title.has_value() ? title.value() : std::string());
    params.push_back(notes.has_value() ? notes.value() : std::string());
    params.push_back(cancelled ? std::string("1") : std::string("0"));
    async_exec_params(sql, std::move(params), cb);
}

void DbPool::async_enqueue_outbox_job(const std::string& job_type, const std::string& payload_json, const std::string& run_after, DbResultCb cb) {
    // Ensure run_after is never NULL: if caller passes empty string, use now() as default.
    const std::string sql = "INSERT INTO outbox_jobs(job_type, payload, run_after) VALUES($1, $2::jsonb, COALESCE(NULLIF($3,'')::timestamptz, now())) RETURNING id";
    async_exec_params(sql, std::vector<std::string>{job_type, payload_json, run_after}, cb);
}

void DbPool::async_claim_next_outbox_job(DbResultCb cb) {
    // Implement atomic claim using a single CTE: pick queued job FOR UPDATE SKIP LOCKED and UPDATE to running in one statement
    auto impl = impl_.get();
    impl->post_task([impl, cb](PGconn*& local_conn) mutable {
        boost::system::error_code ec; DbResult r;
        if (!local_conn) local_conn = impl->connect_one();
        if (!local_conn) { ec = boost::system::errc::make_error_code(boost::system::errc::host_unreachable); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        const char* sql =
            "WITH j AS ("
            "  SELECT id FROM outbox_jobs WHERE status='queued' AND run_after <= now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1"
            ")"
            "UPDATE outbox_jobs o SET status='running', attempts = attempts + 1, updated_at = now()"
            " FROM j WHERE o.id = j.id"
            " RETURNING o.id, o.job_type, o.payload, o.run_after, o.attempts, o.status, o.last_error, o.created_at, o.updated_at";
        PGresult* res = PQexec(local_conn, sql);
        if (!res) { ec = boost::system::errc::make_error_code(boost::system::errc::io_error); post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK) {
            std::string msg = PQresultErrorMessage(res);
            PQclear(res);
            r.ok = false; r.message = msg;
            post_db_result(impl->app_ioc, cb, ec, std::move(r));
            return;
        }
        int nt = PQntuples(res);
        if (nt == 0) { PQclear(res); r.ok = true; post_db_result(impl->app_ioc, cb, ec, std::move(r)); return; }
        int nfields = PQnfields(res);
        for (int i=0;i<nt;++i) {
            r.rows.emplace_back();
            for (int j=0;j<nfields;++j) {
                if (PQgetisnull(res, i, j)) r.rows.back().emplace_back(std::nullopt);
                else r.rows.back().emplace_back(std::string(PQgetvalue(res, i, j)));
            }
        }
        PQclear(res);
        r.ok = true; post_db_result(impl->app_ioc, cb, ec, std::move(r));
    });
}

void DbPool::async_mark_outbox_done(const std::string& job_id, DbResultCb cb) {
    const std::string sql = "UPDATE outbox_jobs SET status='done', updated_at=now() WHERE id=$1 RETURNING id";
    async_exec_params(sql, std::vector<std::string>{job_id}, cb);
}

void DbPool::async_mark_outbox_failed_or_reschedule(const std::string& job_id, const std::string& last_error, const std::string& run_after, const std::string& status, DbResultCb cb) {
    // status should be either 'failed' or 'queued'
    // Ensure run_after is not set to NULL; default to now() when empty
    const std::string sql = "UPDATE outbox_jobs SET status=$2, last_error=$3, run_after = COALESCE(NULLIF($4,'')::timestamptz, now()), updated_at=now() WHERE id=$1 RETURNING id, status";
    async_exec_params(sql, std::vector<std::string>{job_id, status, last_error, run_after}, cb);
}

void DbPool::async_delete_occurrences_in_range(const std::string& event_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb) {
    const std::string sql = "DELETE FROM occurrences WHERE event_id=$1 AND start_ts >= $2 AND start_ts < $3";
    async_exec_params(sql, std::vector<std::string>{event_id, from_ts, to_ts}, cb);
}

void DbPool::async_insert_occurrence(const std::string& event_id, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb) {
    const std::string sql = "INSERT INTO occurrences(event_id, start_ts, end_ts) VALUES($1, NULLIF($2,'')::timestamptz, NULLIF($3,'')::timestamptz) RETURNING id";
    async_exec_params(sql, std::vector<std::string>{event_id, start_ts, end_ts.has_value() ? end_ts.value() : std::string()}, cb);
}

void DbPool::async_list_occurrences(const std::string& calendar_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb) {
    // The query returns occurrences for calendar within range, but applies recurrence_exdates and occurrence_overrides:
    // - Exclude occurrences whose date (::date) is present in recurrence_exdates for the rule_id
    // - Left join occurrence_overrides by rule_id and original_start_ts; if override.is_cancelled = true -> exclude
    // - If override present and not cancelled -> return override fields where provided (title, start_ts, end_ts)
    // Return occurrence rows with helpful recurrence metadata so frontend can
    // determine whether an item is an occurrence of a recurring series.
    // Columns returned (in order):
    //  o.id AS occurrence_id,
    //  e.id AS event_id,
    //  rr.id AS recurrence_rule_id,
    //  title, description, start_ts, end_ts, created_by, created_at, sort_key
    const std::string sql =
        "SELECT o.id AS occurrence_id, "
        "e.id AS event_id, "
        "rr.id AS recurrence_rule_id, "
        "COALESCE(ov.title, e.title) AS title, "
    "COALESCE(ov.notes, e.description, NULL) AS description, "
        "COALESCE(ov.new_start_ts, o.start_ts) AS start_ts, "
        "COALESCE(ov.new_end_ts, o.end_ts) AS end_ts, "
        "e.created_by, o.created_at, COALESCE(ov.new_start_ts, o.start_ts) AS sort_key "
        "FROM occurrences o "
        "JOIN events e ON e.id = o.event_id "
        "LEFT JOIN recurrence_rules rr ON rr.event_id = e.id "
    "LEFT JOIN recurrence_exdates ex ON ex.rule_id = rr.id AND ex.exdate = ((o.start_ts AT TIME ZONE 'UTC')::date) "
        "LEFT JOIN occurrence_overrides ov ON ov.rule_id = rr.id AND ov.original_start_ts = o.start_ts "
        "WHERE e.calendar_id = $1 AND o.start_ts >= $2 AND o.start_ts < $3 "
        "AND ex.rule_id IS NULL "
        "AND (ov.id IS NULL OR ov.is_cancelled = false) "
        "ORDER BY sort_key ASC";
    async_exec_params(sql, std::vector<std::string>{calendar_id, from_ts, to_ts}, cb);
}

} // namespace db
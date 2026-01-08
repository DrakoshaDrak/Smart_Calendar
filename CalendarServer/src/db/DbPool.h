
#pragma once

#include <libpq-fe.h>
#include <optional>
#include <string>
#include <functional>
#include <vector>
#include <memory>
#include <boost/asio.hpp>

namespace db {


using ResultPtr = std::shared_ptr<PGresult>;
using DbCallback = std::function<void(const boost::system::error_code&, ResultPtr)>;


struct DbResult {
    bool ok = false;
    std::string sqlstate;     
    std::string message;      
    std::vector<std::string> columns;
    std::vector<std::vector<std::optional<std::string>>> rows;
    int affected_rows = 0;
};

using DbResultCb = std::function<void(const boost::system::error_code&, DbResult)>;


class DbPool {
public:
    
    DbPool(boost::asio::io_context& app_ioc, const std::string& conninfo, int workers = 4);
    ~DbPool();

    
    void async_exec(const std::string& sql, DbResultCb cb);

    
    void async_exec_params(const std::string& sql, std::vector<std::string> params, DbResultCb cb);

    
    using ScalarIntCb = std::function<void(const boost::system::error_code&, int)>;
    void async_scalar_int(const std::string& sql, ScalarIntCb cb);

    
    void async_insert_user(const std::string& email, const std::string& password_hash, DbResultCb cb);
    void async_get_user_by_email(const std::string& email, DbResultCb cb);
    void async_get_user_by_id(const std::string& id, DbResultCb cb);

    
    void async_create_calendar(std::string owner_id, std::string title, DbResultCb cb);
    void async_list_calendars_for_user(std::string user_id, DbResultCb cb);
    void async_get_calendar(std::string calendar_id, DbResultCb cb);
    void async_add_membership(std::string calendar_id, std::string user_id, int role, DbResultCb cb);
    void async_get_membership(std::string calendar_id, std::string user_id, DbResultCb cb);
    void async_list_memberships(std::string calendar_id, DbResultCb cb);
    void async_update_membership_role(std::string calendar_id, std::string user_id, int role, DbResultCb cb);
    void async_remove_membership(std::string calendar_id, std::string user_id, DbResultCb cb);

    
    void async_create_event(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb);
    
    void async_create_event_with_occurrence(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb);
    void async_create_event_with_recurrence(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, const std::string& freq, int interval, const std::optional<int>& count, const std::optional<std::string>& until_ts, const std::optional<std::vector<int>>& byweekday, const std::vector<std::string>& occ_starts, const std::vector<std::string>& occ_ends, DbResultCb cb);
    void async_list_events(const std::string& calendar_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb);
    void async_get_event(const std::string& calendar_id, const std::string& event_id, DbResultCb cb);
    void async_update_event_full(const std::string& calendar_id, const std::string& event_id, const std::string& title, const std::optional<std::string>& description, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb);
    void async_delete_event(const std::string& calendar_id, const std::string& event_id, DbResultCb cb);

    
    void async_create_task(const std::string& calendar_id, const std::string& created_by, const std::string& title, const std::optional<std::string>& description, const std::optional<std::string>& due_ts, DbResultCb cb);
    void async_list_tasks(const std::string& calendar_id, const std::optional<std::string>& from_ts, const std::optional<std::string>& to_ts, const std::optional<int>& status, DbResultCb cb);
    void async_get_task(const std::string& calendar_id, const std::string& task_id, DbResultCb cb);
    void async_update_task_full(const std::string& calendar_id, const std::string& task_id, const std::string& title, const std::optional<std::string>& description, const std::optional<std::string>& due_ts, int status, DbResultCb cb);
    void async_delete_task(const std::string& calendar_id, const std::string& task_id, DbResultCb cb);

    
    void async_create_recurrence_rule(const std::string& event_id, const std::string& freq, int interval, const std::optional<int>& count, const std::optional<std::string>& until_ts, const std::optional<std::vector<int>>& byweekday, DbResultCb cb);
    void async_delete_occurrences_in_range(const std::string& event_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb);
    void async_insert_occurrence(const std::string& event_id, const std::string& start_ts, const std::optional<std::string>& end_ts, DbResultCb cb);
    void async_list_occurrences(const std::string& calendar_id, const std::string& from_ts, const std::string& to_ts, DbResultCb cb);

    
    void async_add_recurrence_exdate(const std::string& rule_id, const std::string& exdate, DbResultCb cb);
    void async_remove_recurrence_exdate(const std::string& rule_id, const std::string& exdate, DbResultCb cb);

    void async_upsert_occurrence_override(const std::string& rule_id, const std::string& original_start_ts, const std::optional<std::string>& new_start_ts, const std::optional<std::string>& new_end_ts, const std::optional<std::string>& title, const std::optional<std::string>& notes, bool cancelled, DbResultCb cb);

    
    void async_enqueue_outbox_job(const std::string& job_type, const std::string& payload_json, const std::string& run_after, DbResultCb cb);
    void async_claim_next_outbox_job(DbResultCb cb); 
    
    void async_mark_outbox_done(const std::string& job_id, DbResultCb cb);
    void async_mark_outbox_failed_or_reschedule(const std::string& job_id, const std::string& last_error, const std::string& run_after, const std::string& status, DbResultCb cb);

    
    void async_exec_legacy(const std::string& sql, DbCallback cb);
    void async_exec_params_legacy(const std::string& sql, std::vector<std::string> params, DbCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
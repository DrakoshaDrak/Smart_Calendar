#include "OutboxWorker.h"
#include "Materializer.h"
#include "../net/MiniJson.h"
#include "../db/DbPool.h"
#include "../observability/Logging.h"

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <ctime>
#include <algorithm>

using namespace recurrence;

OutboxWorker::OutboxWorker(boost::asio::io_context& ioc, std::shared_ptr<db::DbPool> db)
    : ioc_(ioc), timer_(ioc), db_(db) {}

OutboxWorker::~OutboxWorker() { stop(); }

void OutboxWorker::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return; 
    
    auto self = shared_from_this();
    boost::asio::post(ioc_, [self]{
        self->schedule_next_tick();
    });
}

void OutboxWorker::stop() {
    
    auto self = shared_from_this();
    boost::asio::post(ioc_, [self]{
        self->running_ = false;
        boost::system::error_code ec; self->timer_.cancel(ec);
    });
}

void OutboxWorker::tick() {
    if (!running_) return;
    if (in_flight_) { schedule_next_tick(); return; }
    in_flight_ = true;
    auto self = shared_from_this();
    db_->async_claim_next_outbox_job([self](const boost::system::error_code& ec, const db::DbResult& r){
        self->on_claimed_job(ec, r, nullptr);
    });
}

void OutboxWorker::schedule_next_tick() {
    if (!running_) return;
    auto self = shared_from_this();
    boost::system::error_code ec; timer_.cancel(ec);
    timer_.expires_after(std::chrono::milliseconds(300));
    timer_.async_wait([self](const boost::system::error_code& ec2){ if (!ec2) self->tick(); });
}

void OutboxWorker::complete_and_reschedule() {
    
    in_flight_ = false;
    schedule_next_tick();
}

void OutboxWorker::post_complete_and_reschedule() {
    auto self = shared_from_this();
    boost::asio::post(ioc_, [self]{ self->complete_and_reschedule(); });
}

void OutboxWorker::process_one_job(std::function<void(bool)> cb) {
    auto self = shared_from_this();
    boost::asio::post(ioc_, [self, cb]{
        if (!self->running_) { if (cb) cb(false); return; }
        if (self->in_flight_) { if (cb) cb(false); return; }
        self->in_flight_ = true;
        self->db_->async_claim_next_outbox_job([self, cb](const boost::system::error_code& ec, const db::DbResult& r){
            self->on_claimed_job(ec, r, cb);
        });
    });
}

void OutboxWorker::on_claimed_job(const boost::system::error_code& ec, const db::DbResult& r, std::function<void(bool)> cb) {
    auto self = shared_from_this();
    if (ec) { observability::log_error("outbox.claim_failed"); if (cb) cb(false); post_complete_and_reschedule(); return; }
    if (!r.ok || r.rows.empty()) { if (cb) cb(true); post_complete_and_reschedule(); return; }

    const auto& row = r.rows[0];
    std::string job_id = row.size() > 0 && row[0].has_value() ? row[0].value() : std::string();
    std::string job_type = row.size() > 1 && row[1].has_value() ? row[1].value() : std::string();
    std::string payload = row.size() > 2 && row[2].has_value() ? row[2].value() : std::string();
    int attempts = 0; if (row.size() > 4 && row[4].has_value()) { try { attempts = std::stoi(row[4].value()); } catch(...) { attempts = 0; } }
    if (attempts < 0) attempts = 0;

    if (job_type == "recompute_rule") {
        auto pid = json_extract_string_present(payload, "rule_id");
        if (!pid.first) { observability::log_warn("outbox.bad_payload", {{"payload", payload}, {"job_id", job_id}}); finish_job_failure(job_id, std::string("bad_payload"), attempts, cb); return; }
        auto pcal = json_extract_string_present(payload, "calendar_id");
        if (!pcal.first) { observability::log_warn("outbox.bad_payload", {{"payload", payload}, {"job_id", job_id}}); finish_job_failure(job_id, std::string("bad_payload"), attempts, cb); return; }
        auto prstart = json_extract_string_present(payload, "range_start");
        auto prend = json_extract_string_present(payload, "range_end");
        std::string rule_id = pid.second;
        std::string calendar_id = pcal.second;
        std::string range_start = prstart.first ? prstart.second : std::string();
        std::string range_end = prend.first ? prend.second : std::string();

        std::string sql = "SELECT rr.id, rr.event_id, rr.freq, rr.interval, rr.count, rr.until_ts, rr.byweekday, e.start_ts, e.end_ts, e.calendar_id FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1";
        db_->async_exec_params(sql, std::vector<std::string>{rule_id}, [self, cb, rule_id, job_id, attempts, calendar_id, range_start, range_end](const boost::system::error_code& ec2, const db::DbResult& rrres){
            if (ec2 || !rrres.ok || rrres.rows.empty()) { observability::log_warn("outbox.rule_not_found", {{"rule_id", rule_id}, {"job_id", job_id}}); self->finish_job_failure(job_id, std::string("rule_not_found"), attempts, cb); return; }
            const auto& rrow = rrres.rows[0];
            std::string event_id = rrow.size() > 1 && rrow[1].has_value() ? rrow[1].value() : std::string();
            std::string freq = rrow.size() > 2 && rrow[2].has_value() ? rrow[2].value() : std::string();
            int interval = 1; if (rrow.size() > 3 && rrow[3].has_value()) { try { interval = std::stoi(rrow[3].value()); } catch(...) { interval = 1; } }
            std::optional<int> count = std::nullopt; if (rrow.size() > 4 && rrow[4].has_value() && !rrow[4]->empty()) { try { count = std::stoi(rrow[4].value()); } catch(...) { count = std::nullopt; } }
            std::optional<std::string> until_ts = std::nullopt; if (rrow.size() > 5 && rrow[5].has_value() && !rrow[5]->empty()) until_ts = rrow[5].value();
            std::optional<std::vector<int>> byweekday = std::nullopt;
            if (rrow.size() > 6 && rrow[6].has_value() && !rrow[6]->empty()) {
                std::string s = rrow[6].value(); if (s.size() >= 2 && s.front()=='{' && s.back()=='}') {
                    std::vector<int> vals; std::string inner = s.substr(1, s.size()-2); size_t pos=0; while (pos < inner.size()) { size_t comma = inner.find(',', pos); std::string token = (comma==std::string::npos) ? inner.substr(pos) : inner.substr(pos, comma-pos); try { int v = std::stoi(token); vals.push_back(v); } catch(...) {} if (comma==std::string::npos) break; pos = comma+1; }
                    if (!vals.empty()) byweekday = vals;
                }
            }
            std::string base_start = rrow.size() > 7 && rrow[7].has_value() ? rrow[7].value() : std::string();
            std::optional<std::string> base_end = std::nullopt; if (rrow.size() > 8 && rrow[8].has_value() && !rrow[8]->empty()) base_end = rrow[8].value();
            std::string db_calendar_id = rrow.size() > 9 && rrow[9].has_value() ? rrow[9].value() : std::string();

            if (!calendar_id.empty() && !db_calendar_id.empty() && calendar_id != db_calendar_id) {
                observability::log_warn("outbox.calendar_mismatch", {{"job_id", job_id}, {"payload_cal", calendar_id}, {"db_cal", db_calendar_id}});
                self->finish_job_failure(job_id, std::string("calendar_mismatch"), attempts, cb);
                return;
            }

            recurrence::Rule rule; rule.freq = freq; rule.interval = interval; rule.count = count; rule.until_ts = until_ts; rule.byweekday = byweekday;

            if (range_start.empty() || range_end.empty()) { observability::log_warn("outbox.missing_range", {{"job_rule", rule_id}, {"job_id", job_id}}); self->finish_job_failure(job_id, std::string("missing_range"), attempts, cb); return; }

            auto from_opt = recurrence::parse_iso_z(range_start); auto to_opt = recurrence::parse_iso_z(range_end);
            if (!from_opt.has_value() || !to_opt.has_value()) { observability::log_warn("outbox.bad_range_format", {{"job_id", job_id}}); self->finish_job_failure(job_id, std::string("bad_range_format"), attempts, cb); return; }
            time_t from = *from_opt; time_t to = *to_opt;

            auto occs = recurrence::materialize_occurrences(base_start, base_end, rule, from, to);

            
            self->db_->async_delete_occurrences_in_range(event_id, range_start, range_end, [self, cb, occs = std::move(occs), event_id, job_id, attempts, range_start, range_end](const boost::system::error_code& ec3, const db::DbResult& r3) mutable {
                if (ec3) { observability::log_warn("outbox.delete_failed", {{"event_id", event_id}, {"job_id", job_id}}); self->finish_job_failure(job_id, std::string("delete_failed"), attempts, cb); return; }
                std::vector<std::string> starts; std::vector<std::string> ends;
                for (const auto& p : occs) { starts.push_back(p.first); ends.push_back(p.second.has_value() ? p.second.value() : std::string()); }
                if (starts.empty()) { self->finish_job_success(job_id, cb); return; }
                auto escape_array_elem = [](const std::string& v)->std::string{
                    std::string out; out.reserve(v.size());
                    for (char c : v) {
                        if (c == '\\') out += "\\\\";
                        else if (c == '"') out += "\\\"";
                        else out.push_back(c);
                    }
                    return out;
                };
                auto build_array = [&escape_array_elem](const std::vector<std::string>& vals)->std::string{ if (vals.empty()) return std::string("{}"); std::string out = "{"; for (size_t i=0;i<vals.size();++i) { if (i) out += ","; out += '"'; out += escape_array_elem(vals[i]); out += '"'; } out += "}"; return out; };
                std::string starts_arr = build_array(starts); std::string ends_arr = build_array(ends);
                std::string sql_ins = "INSERT INTO occurrences(event_id, start_ts, end_ts, created_at) SELECT $1, t.start_ts::timestamptz, NULLIF(t.end_ts,'')::timestamptz, now() FROM UNNEST($2::text[], $3::text[]) AS t(start_ts, end_ts) ON CONFLICT (event_id, start_ts) DO NOTHING";
                self->db_->async_exec_params(sql_ins, std::vector<std::string>{event_id, starts_arr, ends_arr}, [self, cb, job_id, attempts](const boost::system::error_code& ec4, const db::DbResult& r4){
                    if (ec4) {
                        observability::log_warn("outbox.insert_failed");
                        self->finish_job_failure(job_id, std::string("insert_failed"), attempts, cb);
                    } else {
                        self->finish_job_success(job_id, cb);
                    }
                });
            });
        });
    } else {
        observability::log_warn("outbox.unknown_job", {{"type", job_type}, {"job_id", job_id}});
        finish_job_failure(job_id, std::string("unknown_job_type"), attempts, cb);
    }
}

void OutboxWorker::finish_job_success(const std::string& job_id, std::function<void(bool)> cb) {
    auto self = shared_from_this();
    db_->async_mark_outbox_done(job_id, [self, cb](const boost::system::error_code& ec, const db::DbResult& r){
        if (ec || !r.ok) { observability::log_warn("outbox.mark_done_failed"); if (cb) cb(false); self->post_complete_and_reschedule(); return; }
        if (cb) cb(true);
        self->post_complete_and_reschedule();
    });
}

void OutboxWorker::finish_job_failure(const std::string& job_id, const std::string& last_error, int attempts, std::function<void(bool)> cb) {
    auto self = shared_from_this();
    const int MAX_ATTEMPTS = 10;
    if (attempts < 0) attempts = 0;
    if (attempts >= MAX_ATTEMPTS) {
        db_->async_mark_outbox_failed_or_reschedule(job_id, last_error, std::string(), std::string("failed"), [self, cb](const boost::system::error_code& ec, const db::DbResult& r){ if (ec) observability::log_warn("outbox.mark_failed_err"); if (cb) cb(false); self->post_complete_and_reschedule(); });
        return;
    }
    int exp = std::min(std::max(attempts, 0), 6);
    int backoff_sec = std::min(3600, 5 * (1 << exp));
    auto tp = std::chrono::system_clock::now() + std::chrono::seconds(backoff_sec);
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buf[64]; std::tm tm{}; gmtime_r(&t, &tm); strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    std::string run_after = std::string(buf);
    db_->async_mark_outbox_failed_or_reschedule(job_id, last_error, run_after, std::string("queued"), [self, cb](const boost::system::error_code& ec, const db::DbResult& r){ if (ec) observability::log_warn("outbox.reschedule_failed"); if (cb) cb(false); self->post_complete_and_reschedule(); });
}

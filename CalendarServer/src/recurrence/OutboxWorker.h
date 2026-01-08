#pragma once

#include <memory>
#include <atomic>
#include <functional>
#include <boost/asio.hpp>

namespace db { struct DbResult; class DbPool; }

namespace recurrence {

class OutboxWorker : public std::enable_shared_from_this<OutboxWorker> {
public:
    OutboxWorker(boost::asio::io_context& ioc, std::shared_ptr<db::DbPool> db);
    ~OutboxWorker();

    void start();
    void stop();

    
    void process_one_job(std::function<void(bool)> cb);

private:
    void tick();
    void on_claimed_job(const boost::system::error_code& ec, const db::DbResult& r, std::function<void(bool)> cb);
    void finish_job_success(const std::string& job_id, std::function<void(bool)> cb);
    void finish_job_failure(const std::string& job_id, const std::string& last_error, int attempts, std::function<void(bool)> cb);
    void schedule_next_tick();
    void complete_and_reschedule();
    void post_complete_and_reschedule();

    boost::asio::io_context& ioc_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<db::DbPool> db_;
    std::atomic_bool running_ = false;
    std::atomic_bool in_flight_ = false;
};

}

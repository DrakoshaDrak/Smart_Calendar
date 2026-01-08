#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <future>
#include "../src/recurrence/OutboxWorker.h"
#include "../src/db/DbPool.h"

int main() {
    try {
        const char* dburl = std::getenv("DATABASE_URL");
        if (!dburl) { std::cerr << "DATABASE_URL required for test" << std::endl; return 2; }
        boost::asio::io_context ioc;
        std::shared_ptr<db::DbPool> db = std::make_shared<db::DbPool>(ioc, std::string(dburl), 2);
        auto worker = std::make_shared<recurrence::OutboxWorker>(ioc, db);

        std::string payload = "{\"rule_id\":\"00000000-0000-0000-0000-000000000000\",\"calendar_id\":\"00000000-0000-0000-0000-000000000000\",\"range_start\":\"2026-01-01T00:00:00Z\",\"range_end\":\"2026-02-01T00:00:00Z\"}";
        std::promise<bool> p;
        auto f = p.get_future();
        db->async_enqueue_outbox_job("recompute_rule", payload, "", [&p](const boost::system::error_code& ec, const db::DbResult& r){ if (ec || !r.ok) p.set_value(false); else p.set_value(true); });
        if (!f.get()) { std::cerr << "enqueue failed" << std::endl; return 2; }

        std::promise<bool> p2; auto f2 = p2.get_future();
        worker->process_one_job([&p2](bool ok){ p2.set_value(ok); });
        std::thread t([&ioc]{ ioc.run(); });
        bool ok = f2.get();
        ioc.stop(); t.join();
        if (!ok) { std::cerr << "worker failed to process job" << std::endl; return 2; }
        std::cout << "exdates_unit ok" << std::endl; return 0;
    } catch (std::exception& e) { std::cerr << "exception: " << e.what() << std::endl; return 2; }
}

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

        
        
        std::promise<bool> pcreate; auto fcreate = pcreate.get_future();
        
        std::string calendar_id;
        
        db->async_exec("INSERT INTO users(email, password_hash) VALUES('t@t.local','x') RETURNING id", [&pcreate, &calendar_id](const boost::system::error_code& ec, const db::DbResult& r){ if (ec || !r.ok || r.rows.empty()) { pcreate.set_value(false); return; } std::string uid = r.rows[0][0].value(); pcreate.set_value(true); });
        if (!fcreate.get()) { std::cerr << "create user failed" << std::endl; return 2; }

        
        std::promise<bool> pcal; auto fcal = pcal.get_future();
        db->async_exec_params("INSERT INTO calendars(title, owner_user_id) VALUES($1,$2) RETURNING id", std::vector<std::string>{"tcal","1"}, [&pcal](const boost::system::error_code& ec, const db::DbResult& r){ if (ec || !r.ok || r.rows.empty()) pcal.set_value(false); else pcal.set_value(true); });
        if (!fcal.get()) { std::cerr << "create calendar failed" << std::endl; return 2; }

        
        std::string payload = "{\"rule_id\":\"00000000-0000-0000-0000-000000000000\",\"calendar_id\":\"00000000-0000-0000-0000-000000000000\",\"range_start\":\"2026-01-01T00:00:00Z\",\"range_end\":\"2026-02-01T00:00:00Z\"}";
        std::promise<bool> penq; auto fenq = penq.get_future();
        db->async_enqueue_outbox_job("recompute_rule", payload, "", [&penq](const boost::system::error_code& ec, const db::DbResult& r){ if (ec || !r.ok) penq.set_value(false); else penq.set_value(true); });
        if (!fenq.get()) { std::cerr << "enqueue failed" << std::endl; return 2; }

        
        std::promise<bool> p2; auto f2 = p2.get_future();
        worker->process_one_job([&p2](bool ok){ p2.set_value(ok); });
        std::thread t([&ioc]{ ioc.run(); });
        bool ok = f2.get();
        ioc.stop(); t.join();
        if (!ok) { std::cerr << "worker failed to process job" << std::endl; return 2; }
        std::cout << "overrides_unit ok" << std::endl; return 0;
    } catch (std::exception& e) { std::cerr << "exception: " << e.what() << std::endl; return 2; }
}

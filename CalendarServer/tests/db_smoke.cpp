#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <boost/asio.hpp>
#include "db/DbPool.h"

int main(int argc, char** argv) {
    const char* url = std::getenv("DATABASE_URL");
    if (!url) {
        std::cerr << "DATABASE_URL required\n";
        return 2;
    }

    boost::asio::io_context ioc;

    
    auto work_guard = boost::asio::make_work_guard(ioc);

    db::DbPool pool(ioc, std::string(url), 2);

    std::atomic<bool> done{false};
    std::atomic<int> exit_code{1};

    std::string email =
        std::string("test_") +
        std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
        "@example.local";

    pool.async_insert_user(email, "hash", [&](const boost::system::error_code& ec, db::DbResult r) {
        if (ec || !r.ok) {
            std::cerr << "insert error: " << (ec ? ec.message() : r.message) << "\n";
            exit_code = 1;
            done = true;
            return;
        }

        pool.async_get_user_by_email(email, [&](const boost::system::error_code& ec2, db::DbResult r2) {
            if (ec2 || !r2.ok) {
                std::cerr << "select error: " << (ec2 ? ec2.message() : r2.message) << "\n";
                exit_code = 1;
                done = true;
                return;
            }
            if (r2.rows.empty() || r2.rows[0].size() < 2) {
                std::cerr << "no result\n";
                exit_code = 1;
                done = true;
                return;
            }

            const std::string& em = r2.rows[0][1].has_value() ? r2.rows[0][1].value() : std::string();
            if (email == em) {
                
                std::string owner_id = r2.rows[0][0].has_value() ? r2.rows[0][0].value() : std::string();
                
                  pool.async_create_calendar(owner_id, "Test Calendar", [owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec3, db::DbResult r3) {
                    if (ec3 || !r3.ok || r3.rows.empty()) { std::cerr << "create calendar failed\n"; exit_code = 1; done = true; return; }
                        std::string cal_id = r3.rows[0][0].has_value() ? r3.rows[0][0].value() : std::string();
                    
                    std::string reader_email = std::string("reader_") + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
                    pool.async_insert_user(reader_email, "h", [cal_id, owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec4, db::DbResult r4) {
                        if (ec4 || !r4.ok) { std::cerr << "insert reader failed\n"; exit_code = 1; done = true; return; }
                        std::string reader_id = r4.rows[0][0].has_value() ? r4.rows[0][0].value() : std::string();
                        
                            pool.async_add_membership(cal_id, reader_id, 0, [cal_id, reader_id, owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec5, db::DbResult r5) {
                            (void)cal_id; (void)r5;
                            if (ec5 || !r5.ok) { std::cerr << "add membership failed\n"; exit_code = 1; done = true; return; }
                            
                            pool.async_list_calendars_for_user(reader_id, [cal_id, reader_id, owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec6, db::DbResult r6) {
                                if (ec6 || !r6.ok) { std::cerr << "list for reader failed\n"; exit_code = 1; done = true; return; }
                                bool found = false;
                                for (auto &row : r6.rows) if (!row.empty() && row[0].has_value() && row[0].value() == cal_id) found = true;
                                if (!found) { std::cerr << "reader cannot see calendar\n"; exit_code = 1; done = true; return; }
                                
                                    pool.async_update_membership_role(cal_id, reader_id, 1, [cal_id, reader_id, owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec7, db::DbResult r7) {
                                    if (ec7 || !r7.ok) { std::cerr << "promote failed\n"; exit_code = 1; done = true; return; }
                                    
                                        pool.async_get_membership(cal_id, reader_id, [cal_id, reader_id, owner_id, &pool, &exit_code, &done](const boost::system::error_code& ec8, db::DbResult r8) {
                                        if (ec8 || !r8.ok || r8.rows.empty()) { std::cerr << "get membership failed\n"; exit_code = 1; done = true; return; }
                                        int role = 0;
                                        if (r8.rows[0][2].has_value()) role = std::stoi(r8.rows[0][2].value());
                                        if (role != 1) { std::cerr << "role not updated\n"; exit_code = 1; done = true; return; }
                                        
                                        pool.async_exec_params(std::string("DELETE FROM calendars WHERE id=$1"), std::vector<std::string>{cal_id}, [cal_id, &exit_code, &done](const boost::system::error_code& ec10, db::DbResult r10) {
                                            if (ec10 || !r10.ok) { std::cerr << "cleanup failed\n"; exit_code = 1; done = true; return; }
                                            std::cout << "db_smoke extended ok\n";
                                            exit_code = 0; done = true; return;
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
                return;
            }
            std::cerr << "unexpected result\n";
            exit_code = 1;
            done = true;
            return;
        });
    });

    std::thread t([&] { ioc.run(); });

    
    
    for (int i = 0; i < 100 && !done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    
    work_guard.reset();
    ioc.stop();
    if (t.joinable()) t.join();

    if (!done.load()) {
        std::cerr << "timeout waiting for db_smoke\n";
        return 1;
    }

    return exit_code.load();
}

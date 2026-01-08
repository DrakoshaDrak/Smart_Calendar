#define UNIT_TEST 1
#include "libpq-fe.h"
#include <boost/asio.hpp>
#include <future>
#include <iostream>
#include <thread>
#include "db/DbPool.h"
#include "observability/Logging.h"
#include "test_util.h"

using namespace db;

int main() {
  fake_pg_clear_queue();
  fake_pg_set_connect_ok(1);
  observability::set_log_level(4);

  boost::asio::io_context ioc;
  auto guard = boost::asio::make_work_guard(ioc.get_executor());
  std::promise<std::thread::id> pid; auto fid = pid.get_future();
  std::thread app_thread([&]{ pid.set_value(std::this_thread::get_id()); ioc.run(); });
  std::thread::id app_tid = fid.get();

  DbPool pool(ioc, "dbname=test", 1);

  
  fake_pg_queue_null(); fake_pg_queue_null();
  Waiter w;
  pool.async_exec("SELECT null", [&](const boost::system::error_code& ec, DbResult r){
    std::unique_lock<std::mutex> lk(w.mu);
    if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread" << std::endl; std::exit(2); }
    if (!ec && r.ok) { std::cerr << "expected error or non-ok result" << std::endl; std::exit(2); }
    w.done++;
    lk.unlock(); w.cv.notify_one();
  });
  {
    std::unique_lock<std::mutex> lk(w.mu);
    if (!w.cv.wait_for(lk, std::chrono::seconds(2), [&]{ return w.done == 1; })) {
      std::cerr << "error-case callback not called" << std::endl; guard.reset(); ioc.stop(); app_thread.join(); return 2;
    }
  }

  
  fake_pg_clear_queue();
  fake_pg_queue_response(PGRES_FATAL_ERROR, "boom", "23505", "", "", "");
  w.done = 0;
  pool.async_exec("INSERT", [&](const boost::system::error_code& ec, DbResult r){
    std::unique_lock<std::mutex> lk(w.mu);
    if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread" << std::endl; std::exit(2); }
    if (r.ok) { std::cerr << "expected not ok for fatal" << std::endl; std::exit(2); }
    if (r.sqlstate != "23505") { std::cerr << "sqlstate mismatch" << std::endl; std::exit(2); }
    if (r.message.find("boom") == std::string::npos) { std::cerr << "message mismatch" << std::endl; std::exit(2); }
    w.done++;
    lk.unlock(); w.cv.notify_one();
  });
  {
    std::unique_lock<std::mutex> lk(w.mu);
    if (!w.cv.wait_for(lk, std::chrono::seconds(2), [&]{ return w.done == 1; })) {
      std::cerr << "fatal-case callback not called" << std::endl; guard.reset(); ioc.stop(); app_thread.join(); return 2;
    }
  }

  guard.reset(); ioc.stop(); app_thread.join();
  std::cout << "dbpool_unit_errors ok" << std::endl;
  return 0;
}

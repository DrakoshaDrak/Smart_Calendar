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

  
  fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id,name", "1,<NULL>", "");
  DbPool pool(ioc, "dbname=test", 1);
  Waiter w;
  pool.async_exec("SELECT null", [&](const boost::system::error_code& ec, DbResult r){
    std::unique_lock<std::mutex> lk(w.mu);
    if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread" << std::endl; std::exit(2); }
    if (!r.ok) { std::cerr << "expected ok" << std::endl; std::exit(2); }
    if (r.rows.size() != 1) { std::cerr << "rows size" << std::endl; std::exit(2); }
    if (r.rows[0][1].has_value()) { std::cerr << "expected null" << std::endl; std::exit(2); }
    w.done++;
    lk.unlock(); w.cv.notify_one();
  });
  {
    std::unique_lock<std::mutex> lk(w.mu);
    if (!w.cv.wait_for(lk, std::chrono::seconds(2), [&]{ return w.done == 1; })) {
      std::cerr << "null callback not called" << std::endl; guard.reset(); ioc.stop(); app_thread.join(); return 2;
    }
  }

  
  fake_pg_clear_queue(); w.done = 0;
  fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id,name", "1,", "");
  pool.async_exec("SELECT empty", [&](const boost::system::error_code& ec, DbResult r){
    std::unique_lock<std::mutex> lk(w.mu);
    if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread" << std::endl; std::exit(2); }
    if (!r.ok) { std::cerr << "expected ok" << std::endl; std::exit(2); }
    if (r.rows.size() != 1) { std::cerr << "rows size" << std::endl; std::exit(2); }
    if (!r.rows[0][1].has_value()) { std::cerr << "expected empty string, not null" << std::endl; std::exit(2); }
    if (r.rows[0][1].value() != "") { std::cerr << "expected empty string value" << std::endl; std::exit(2); }
    w.done++;
    lk.unlock(); w.cv.notify_one();
  });
  {
    std::unique_lock<std::mutex> lk(w.mu);
    if (!w.cv.wait_for(lk, std::chrono::seconds(2), [&]{ return w.done == 1; })) {
      std::cerr << "empty string callback not called" << std::endl; guard.reset(); ioc.stop(); app_thread.join(); return 2;
    }
  }

  guard.reset(); ioc.stop(); app_thread.join();
  std::cout << "dbpool_unit_nulls ok" << std::endl;
  return 0;
}

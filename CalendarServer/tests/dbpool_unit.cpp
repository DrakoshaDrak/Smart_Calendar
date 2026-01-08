#define UNIT_TEST 1
#include "libpq-fe.h"
#include <boost/asio.hpp>
#include <iostream>
#include <atomic>
#include <thread>
#include "db/DbPool.h"

using namespace db;

int main() {
  boost::asio::io_context app_ioc;
  
  fake_pg_clear_queue();
  fake_pg_set_connect_ok(1);

  
  fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id,name", "1,alice;2,bob", "");

  
  auto guard = boost::asio::make_work_guard(app_ioc.get_executor());
  std::promise<std::thread::id> pid;
  auto fid = pid.get_future();
  std::thread app_thread([&]{ pid.set_value(std::this_thread::get_id()); app_ioc.run(); });
  std::thread::id app_tid = fid.get();

  DbPool pool(app_ioc, "dbname=test", 1);
  
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  std::atomic<int> called{0};

  
  pool.async_exec("SELECT 1", [&](const boost::system::error_code& ec, DbResult r){
    called.fetch_add(1);
    
  
  if (std::this_thread::get_id() != app_tid) { std::cerr << "callback did not run on app_ioc thread" << std::endl; std::exit(2); }
    if (ec) { std::cerr << "unexpected ec" << std::endl; std::exit(2); }
    if (!r.ok) { std::cerr << "result not ok" << std::endl; std::exit(2); }
    if ((int)r.columns.size() != 2) { std::cerr << "columns mismatch" << std::endl; std::exit(2); }
    if ((int)r.rows.size() != 2) { std::cerr << "rows mismatch" << std::endl; std::exit(2); }
    if (r.rows[0][1].value() != "alice") { std::cerr << "first row mismatch" << std::endl; std::exit(2); }
  });

  
  for (int i=0;i<200 && called.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  if (called.load() != 1) { std::cerr << "callback not called" << std::endl; guard.reset(); app_ioc.stop(); app_thread.join(); return 2; }

  
  fake_pg_clear_queue();
  
  fake_pg_queue_null();
  fake_pg_queue_null();
  called.store(0);
  pool.async_exec("SELECT 2", [&](const boost::system::error_code& ec, DbResult r){
    called.fetch_add(1);
    
    if (!ec && r.ok) { std::cerr << "expected error or non-ok result" << std::endl; std::exit(2); }
  });
  for (int i=0;i<200 && called.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  if (called.load() != 1) { std::cerr << "error callback not called" << std::endl; guard.reset(); app_ioc.stop(); app_thread.join(); return 2; }

  
  fake_pg_clear_queue();
  for (int i=0;i<10;++i) fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id", std::to_string(i).c_str(), "");
  std::atomic<int> total{0};
  std::vector<std::thread> ths;
  for (int i=0;i<5;++i) ths.emplace_back([&]{
    pool.async_exec("SELECT x", [&](const boost::system::error_code& ec, DbResult r){
      if (ec) std::cerr << "unexpected ec in concurrency" << std::endl;
      total.fetch_add(1);
    });
  });
  for (auto &t: ths) t.join();
  for (int i=0;i<300 && total.load()<5;++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  if (total.load() != 5) { std::cerr << "concurrency callbacks mismatch: " << total.load() << std::endl; guard.reset(); app_ioc.stop(); app_thread.join(); return 2; }

  
  fake_pg_clear_queue();
  
  fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id", "42", "");
  called.store(0);
  {
    DbPool short_pool(app_ioc, "dbname=test", 1);
    short_pool.async_exec("SELECT slow", [&](const boost::system::error_code& ec, DbResult r){ called.fetch_add(1); });
    
  }
  for (int i=0;i<200 && called.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));

  
  if (called.load() > 1) { std::cerr << "too many callbacks after shutdown" << std::endl; guard.reset(); app_ioc.stop(); app_thread.join(); return 2; }

  
  guard.reset(); app_ioc.stop(); app_thread.join();

  
  
  {
    fake_pg_clear_queue();
    
    fake_pg_queue_response(PGRES_FATAL_ERROR, "boom", "23505", "", "", "");
    boost::asio::io_context ioc2; auto guard2 = boost::asio::make_work_guard(ioc2.get_executor()); std::thread t2([&]{ ioc2.run(); });
    DbPool p2(ioc2, "dbname=test", 1);
    std::atomic<int> called2{0};
    p2.async_exec("INSERT ...", [&](const boost::system::error_code& ec, DbResult r){
      called2.fetch_add(1);
      if (r.ok) { std::cerr << "expected not ok for fatal error" << std::endl; std::exit(2); }
      if (r.message.find("boom") == std::string::npos) { std::cerr << "message mismatch" << std::endl; std::exit(2); }
      if (r.sqlstate != "23505") { std::cerr << "sqlstate mismatch: " << r.sqlstate << std::endl; std::exit(2); }
    });
    for (int i=0;i<200 && called2.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    guard2.reset(); ioc2.stop(); t2.join();
    if (called2.load() != 1) { std::cerr << "sqlstate test callback not called" << std::endl; return 2; }
  }

  {
    fake_pg_clear_queue();
    
    fake_pg_queue_response(PGRES_COMMAND_OK, "", "", "", "", "7");
    boost::asio::io_context ioc3; auto guard3 = boost::asio::make_work_guard(ioc3.get_executor()); std::thread t3([&]{ ioc3.run(); });
    DbPool p3(ioc3, "dbname=test", 1);
    std::atomic<int> called3{0};
    p3.async_exec("UPDATE ...", [&](const boost::system::error_code& ec, DbResult r){
      called3.fetch_add(1);
      if (!r.ok) { std::cerr << "expected ok for command" << std::endl; std::exit(2); }
      if (r.affected_rows != 7) { std::cerr << "affected_rows mismatch: " << r.affected_rows << std::endl; std::exit(2); }
    });
    for (int i=0;i<200 && called3.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    guard3.reset(); ioc3.stop(); t3.join();
    if (called3.load() != 1) { std::cerr << "affected_rows callback not called" << std::endl; return 2; }
  }

  {
    fake_pg_clear_queue();
    
    fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id,name", "1,<NULL>", "");
    boost::asio::io_context ioc4; auto guard4 = boost::asio::make_work_guard(ioc4.get_executor()); std::thread t4([&]{ ioc4.run(); });
    DbPool p4(ioc4, "dbname=test", 1);
    std::atomic<int> called4{0};
    p4.async_exec("SELECT ...", [&](const boost::system::error_code& ec, DbResult r){
      called4.fetch_add(1);
      if (!r.ok) { std::cerr << "expected ok for tuples" << std::endl; std::exit(2); }
      if (r.rows.size() != 1) { std::cerr << "rows size" << std::endl; std::exit(2); }
      if (r.rows[0][1].has_value()) { std::cerr << "expected null in second column" << std::endl; std::exit(2); }
    });
    for (int i=0;i<200 && called4.load()==0;++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    guard4.reset(); ioc4.stop(); t4.join();
    if (called4.load() != 1) { std::cerr << "null field callback not called" << std::endl; return 2; }
  }

  std::cout << "dbpool_unit ok" << std::endl;
  return 0;
}

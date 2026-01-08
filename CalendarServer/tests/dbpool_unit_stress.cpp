#define UNIT_TEST 1
#include "libpq-fe.h"
#include <boost/asio.hpp>
#include <future>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
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

  const int N = 200; 
  const int worker_count = 4;
  const int M = 8; 

  
  for (int i = 0; i < N; ++i) {
    fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id", "42", "");
  }

  DbPool pool(ioc, "dbname=test", worker_count);

  Waiter w;
  std::atomic<int> callbacks{0};

  
  std::vector<std::thread> clients;
  for (int t = 0; t < M; ++t) {
    clients.emplace_back([&]{
      int per = N / M;
      for (int i = 0; i < per; ++i) {
        pool.async_exec("SELECT 42", [&](const boost::system::error_code& ec, DbResult r){
          std::unique_lock<std::mutex> lk(w.mu);
          if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread" << std::endl; std::exit(2); }
          if (!r.ok) { std::cerr << "unexpected not-ok in stress" << std::endl; std::exit(2); }
          ++callbacks;
          w.done++;
          lk.unlock(); w.cv.notify_one();
        });
      }
    });
  }

  
  {
    std::unique_lock<std::mutex> lk(w.mu);
    if (!w.cv.wait_for(lk, std::chrono::seconds(2), [&]{ return w.done == N; })) {
      std::cerr << "stress: not all callbacks completed (got " << w.done << ")" << std::endl;
      
      for (auto &th : clients) th.join();
      guard.reset(); ioc.stop(); app_thread.join();
      return 2;
    }
  }

  
  for (auto &th : clients) th.join();

  
  {
    
    const int S = 20;
    for (int i = 0; i < S; ++i) fake_pg_queue_response(PGRES_TUPLES_OK, "", "", "id", "1", "");
    std::atomic<int> s_callbacks{0};
    Waiter sw;
    {
      DbPool short_pool(ioc, "dbname=test", 2);
      for (int i = 0; i < S; ++i) {
        short_pool.async_exec("SELECT 1", [&](const boost::system::error_code& ec, DbResult r){
          std::unique_lock<std::mutex> lk(sw.mu);
          if (std::this_thread::get_id() != app_tid) { std::cerr << "callback not on app_ioc thread (shutdown)" << std::endl; std::exit(2); }
          s_callbacks.fetch_add(1);
          sw.done++;
          lk.unlock(); sw.cv.notify_one();
        });
      }
      
    }

    
    {
      std::unique_lock<std::mutex> lk(sw.mu);
      sw.cv.wait_for(lk, std::chrono::milliseconds(300));
    }

    
    if (s_callbacks.load() > S) {
      std::cerr << "shutdown: more callbacks than scheduled" << std::endl; guard.reset(); ioc.stop(); app_thread.join(); return 2;
    }
  }

  guard.reset(); ioc.stop(); app_thread.join();
  std::cout << "dbpool_unit_stress ok" << std::endl;
  return 0;
}

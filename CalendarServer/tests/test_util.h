
#pragma once

#include <condition_variable>
#include <mutex>

struct Waiter {
  std::mutex mu;
  std::condition_variable cv;
  int done = 0;
};

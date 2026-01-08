#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "Router.h"
#include "../db/DbPool.h"
#include <memory>
#include "cache/RedisClient.h"
#include <string>

class HttpServer {
public:
    HttpServer(boost::asio::io_context& ioc, unsigned short port, Router& router, bool metrics_enabled, bool access_log, std::shared_ptr<RedisClient> redis = nullptr, bool cache_enabled = true, int cache_ttl_sec = 60, bool cache_require_full_month_range = true, bool rate_limit_enabled = false, int rate_limit_limit = 0, int rate_limit_window_ms = 0, std::shared_ptr<db::DbPool> db = nullptr, std::shared_ptr<boost::asio::thread_pool> cpu_pool = nullptr, const std::string& jwt_secret = "");
    void run();
private:
    void do_accept();
    boost::asio::io_context& ioc_;
    boost::asio::ip::tcp::acceptor acceptor_;
    Router& router_;
    bool metrics_enabled_;
    bool access_log_;
    std::shared_ptr<RedisClient> redis_;
    bool cache_enabled_ = true;
    int cache_ttl_sec_ = 60;
    bool cache_require_full_month_range_ = true;
    std::shared_ptr<db::DbPool> db_;
    std::shared_ptr<boost::asio::thread_pool> cpu_pool_;
    std::string jwt_secret_;
    bool rate_limit_enabled_ = false;
    int rate_limit_limit_ = 0;
    int rate_limit_window_ms_ = 0;
};

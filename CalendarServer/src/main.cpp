#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <string_view>
#include <functional>
#include <memory>
#include <cstdlib>
#include <thread>
#include "net/Router.h"
#include "net/HttpServer.h"
#include "observability/Metrics.h"
#include "observability/Logging.h"
#include "config/Config.h"
#include "db/DbPool.h"

using config::Config;
using observability::log_info;
using observability::log_warn;
using observability::log_error;
using observability::set_log_level;

int main(int argc, char** argv) {
    auto cfg = Config::from_env(argc, argv);
    unsigned short port = cfg.port;
    int lvl = 2;
    switch (cfg.log_level) {
        case Config::LogLevel::DEBUG: lvl = 1; break;
        case Config::LogLevel::INFO: lvl = 2; break;
        case Config::LogLevel::WARN: lvl = 3; break;
        case Config::LogLevel::ERROR: lvl = 4; break;
    }
    set_log_level(lvl);

    try {
        boost::asio::io_context io;

        
        if (cfg.jwt_secret.empty()) {
            std::cerr << "fatal: JWT_SECRET environment variable is not set\n";
            return 2;
        }

        Router router;

        router.add_route("GET", "/health", [](const Request& req) {
            Response res{boost::beast::http::status::ok, req.version()};
            res.set(boost::beast::http::field::content_type, "application/json; charset=utf-8");
            res.keep_alive(req.keep_alive());
            res.body() = "{\"status\":\"ok\"}";
            res.prepare_payload();
            return res;
        });
        if (cfg.metrics_enabled) {
            router.add_route("GET", "/metrics", [](const Request& req) {
                Response res{boost::beast::http::status::ok, req.version()};
                res.set(boost::beast::http::field::content_type, "text/plain; version=0.0.4");
                res.keep_alive(req.keep_alive());
                res.body() = observability::Metrics::instance().scrape();
                res.prepare_payload();
                return res;
            });
        }

    std::shared_ptr<db::DbPool> dbpool;
    if (!cfg.database_url.empty()) dbpool = std::make_shared<db::DbPool>(io, cfg.database_url, cfg.db_workers);
        else log_warn("db_not_configured", {});

        std::shared_ptr<RedisClient> redis_client = nullptr;
        if (!cfg.redis_host.empty()) {
            redis_client = std::make_shared<RedisClient>(io, cfg.redis_host, cfg.redis_port, cfg.redis_pass);
            try { redis_client->start(); } catch (...) { log_warn("redis_start_failed", {{"host", cfg.redis_host}}); redis_client = nullptr; }
        }

        
        router.add_route("GET", "/auth/ping", [](const Request& req) {
            Response res{boost::beast::http::status::ok, req.version()};
            res.set(boost::beast::http::field::content_type, "application/json; charset=utf-8");
            res.keep_alive(req.keep_alive());
            res.body() = "{\"status\":\"ok\"}";
            res.prepare_payload();
            return res;
        });

        

        
        auto cpu_pool = std::make_shared<boost::asio::thread_pool>(std::max(1u, std::thread::hardware_concurrency()));

    HttpServer server(io, port, router, cfg.metrics_enabled, cfg.access_log, redis_client, cfg.cache_enabled, cfg.cache_ttl_sec, cfg.cache_require_full_month_range, cfg.rate_limit_enabled, cfg.rate_limit_limit, cfg.rate_limit_window_ms, dbpool, cpu_pool, cfg.jwt_secret);
        log_info("server_start", {{"port", int64_t(port)}});
        server.run();
        io.run();
    } catch (const std::exception& e) {
        std::cerr << "server error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

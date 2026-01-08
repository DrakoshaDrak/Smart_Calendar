#pragma once

#include <cstdint>
#include <string>

namespace config {

struct Config {
    enum class LogLevel { DEBUG, INFO, WARN, ERROR };
    uint16_t port = 8080;
    LogLevel log_level = LogLevel::INFO;
    bool metrics_enabled = true;
    bool access_log = true;
    std::string redis_host = "127.0.0.1";
    uint16_t redis_port = 6379;
    bool cache_enabled = true;
    int cache_ttl_sec = 60;
    bool cache_require_full_month_range = true;
    bool rate_limit_enabled = true;
    int rate_limit_limit = 5;
    int rate_limit_window_ms = 1000;
    std::string database_url;
    int db_workers = 16;
    std::string jwt_secret;
    std::string redis_pass;
    static Config from_env(int argc, char** argv);
};

}

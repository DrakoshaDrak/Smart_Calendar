#include "Config.h"
#include <cstdlib>
#include <string>
#include <algorithm>

namespace config {

static std::string getenv_or(const char* name, const char* def) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string(def);
}

static Config::LogLevel parse_level(const std::string& s) {
    std::string u = s;
    std::transform(u.begin(), u.end(), u.begin(), ::toupper);
    if (u == "DEBUG") return Config::LogLevel::DEBUG;
    if (u == "WARN") return Config::LogLevel::WARN;
    if (u == "ERROR") return Config::LogLevel::ERROR;
    return Config::LogLevel::INFO;
}

Config Config::from_env(int argc, char** argv) {
    Config c;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--port" && i+1 < argc) c.port = static_cast<uint16_t>(std::stoi(argv[i+1]));
    }
    auto lp = getenv_or("PORT", "8080");
    try { c.port = static_cast<uint16_t>(std::stoi(lp)); } catch(...) {}
    c.log_level = parse_level(getenv_or("LOG_LEVEL", "INFO"));
    c.metrics_enabled = getenv_or("METRICS_ENABLED", "1") != "0";
    c.access_log = getenv_or("ACCESS_LOG", "1") != "0";
    c.redis_host = getenv_or("REDIS_HOST", "127.0.0.1");
    try { c.redis_port = static_cast<uint16_t>(std::stoi(getenv_or("REDIS_PORT", "6379"))); } catch(...) {}
    c.rate_limit_enabled = getenv_or("RATE_LIMIT_ENABLED", "1") != "0";
    try { c.rate_limit_limit = std::stoi(getenv_or("RATE_LIMIT_LIMIT", "5")); } catch(...) {}
    try { c.rate_limit_window_ms = std::stoi(getenv_or("RATE_LIMIT_WINDOW_MS", "1000")); } catch(...) {}
    c.database_url = getenv_or("DATABASE_URL", "");
    c.cache_enabled = getenv_or("CACHE_ENABLED", "1") != "0";
    try { c.cache_ttl_sec = std::stoi(getenv_or("CACHE_TTL_SEC", "60")); } catch(...) {}
    c.cache_require_full_month_range = getenv_or("CACHE_REQUIRE_FULL_MONTH_RANGE", "1") != "0";

    
    try {
        auto w = getenv_or("DB_WORKERS", "");
        if (!w.empty()) c.db_workers = std::stoi(w);
        else c.db_workers = std::stoi(getenv_or("DB_POOL_SIZE", "16"));
    } catch(...) {}
    
    c.db_workers = std::clamp(c.db_workers, 1, 256);
    c.jwt_secret = getenv_or("JWT_SECRET", "");
    c.redis_pass = getenv_or("REDIS_PASS", "");
    return c;
}

}


#include <cstdlib>
#include <iostream>
#include <string>
#include "config/Config.h"

static void safe_unsetenv(const char* name) {
#ifdef _WIN32
    
#else
    unsetenv(name);
#endif
}

int main() {
    
    safe_unsetenv("PORT");
    safe_unsetenv("LOG_LEVEL");
    safe_unsetenv("DATABASE_URL");
    safe_unsetenv("JWT_SECRET");

    
    {
        auto c = config::Config::from_env(0, nullptr);
        if (c.port != 8080) { std::cerr << "default port mismatch: " << c.port << "\n"; return 1; }
        if (c.log_level != config::Config::LogLevel::INFO) { std::cerr << "default log level mismatch\n"; return 1; }
    }

    
    setenv("PORT", "9090", 1);
    setenv("LOG_LEVEL", "DEBUG", 1);
    setenv("DATABASE_URL", "postgres://user:pass@localhost/db", 1);
    setenv("JWT_SECRET", "s3cr3t", 1);
    {
        auto c = config::Config::from_env(0, nullptr);
        if (c.port != 9090) { std::cerr << "env PORT not applied: " << c.port << "\n"; return 1; }
        if (c.log_level != config::Config::LogLevel::DEBUG) { std::cerr << "env LOG_LEVEL not applied\n"; return 1; }
        if (c.database_url != "postgres://user:pass@localhost/db") { std::cerr << "env DATABASE_URL not applied\n"; return 1; }
        if (c.jwt_secret != "s3cr3t") { std::cerr << "env JWT_SECRET not applied\n"; return 1; }
    }

    
    setenv("PORT", "notanumber", 1);
    {
        auto c = config::Config::from_env(0, nullptr);
        
        if (c.port != 8080 && c.port != 9090) { std::cerr << "invalid PORT parsing produced unexpected port: " << c.port << "\n"; return 1; }
    }

    setenv("PORT", "-1", 1);
    {
        auto c = config::Config::from_env(0, nullptr);
        
        (void)c; 
    }

    
    safe_unsetenv("PORT");
    safe_unsetenv("LOG_LEVEL");
    safe_unsetenv("DATABASE_URL");
    safe_unsetenv("JWT_SECRET");

    std::cout << "config_unit ok\n";
    return 0;
}

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <sstream>

namespace observability {

struct MetricsKey {
    std::string path;
    std::string method;
    int code;
    bool operator==(MetricsKey const& o) const noexcept {
        return path == o.path && method == o.method && code == o.code;
    }
};

struct MetricsKeyHash {
    size_t operator()(MetricsKey const& k) const noexcept {
        size_t seed = 0;
        auto mix = [&](size_t v){ seed ^= v + 0x9e3779b97f4a7c15ULL + (seed<<6) + (seed>>2); };
        mix(std::hash<std::string>()(k.path));
        mix(std::hash<std::string>()(k.method));
        mix(std::hash<int>()(k.code));
        return seed;
    }
};

class Metrics {
public:
    static Metrics& instance();
    void inc(const std::string& path, const std::string& method, int code);
    void observe_latency(const std::string& path, const std::string& method, double latency_ms);
    std::string scrape() const;
private:
    Metrics();
    std::unordered_map<MetricsKey, uint64_t, MetricsKeyHash> map_;
    struct HistData {
        std::vector<uint64_t> buckets;
        double sum = 0.0;
        uint64_t count = 0;
    };
    std::unordered_map<MetricsKey, HistData, MetricsKeyHash> hist_;
    mutable std::mutex mu_;
};

} 

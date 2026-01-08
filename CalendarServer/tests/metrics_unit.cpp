#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <regex>
#include <unordered_map>
#include <limits>
#include <cmath>
#include "../src/observability/Metrics.h"

using namespace observability;


static uint64_t parse_counter(const std::string& scrape, const std::string& path, const std::string& method, int code) {
    std::regex re("http_requests_total\\{path=\"" + path + "\",method=\"" + method + "\",code=\"" + std::to_string(code) + "\"\}\\s+([0-9]+)");
    std::smatch m;
    if (std::regex_search(scrape, m, re)) {
        return std::stoull(m[1].str());
    }
    return 0;
}

static std::unordered_map<double, uint64_t> parse_buckets(const std::string& scrape, const std::string& path, const std::string& method) {
    std::unordered_map<double, uint64_t> out;
    std::regex re("http_request_duration_ms_bucket\\{path=\"" + path + "\",method=\"" + method + "\",le=\"([0-9+.Inf]+)\"\}\\s+([0-9]+)");
    std::sregex_iterator it(scrape.begin(), scrape.end(), re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        double bucket;
        std::string b = (*it)[1].str();
        if (b == "+Inf") bucket = std::numeric_limits<double>::infinity();
        else bucket = std::stod(b);
        uint64_t val = std::stoull((*it)[2].str());
        out[bucket] = val;
    }
    return out;
}

static double parse_sum(const std::string& scrape, const std::string& path, const std::string& method) {
    std::regex re("http_request_duration_ms_sum\\{path=\"" + path + "\",method=\"" + method + "\"\}\\s+([0-9.+-eE]+)");
    std::smatch m;
    if (std::regex_search(scrape, m, re)) {
        return std::stod(m[1].str());
    }
    return 0.0;
}

int main() {
    auto &m = Metrics::instance();

    
    m.inc("/test", "GET", 200);
    m.inc("/test", "GET", 200);
    m.inc("/test", "GET", 200);

    std::string s = m.scrape();
    uint64_t cnt = parse_counter(s, "/test", "GET", 200);
    if (cnt != 3) {
        std::cerr << "counter expected 3 got " << cnt << "\n";
        return 1;
    }

    
    m.observe_latency("/lat", "GET", 10.0);
    m.observe_latency("/lat", "GET", 20.0);
    m.observe_latency("/lat", "GET", 30.0);
    m.observe_latency("/lat", "GET", 100.0);
    m.observe_latency("/lat", "GET", 1000.0);

    s = m.scrape();
    auto buckets = parse_buckets(s, "/lat", "GET");
    double sum = parse_sum(s, "/lat", "GET");

    
    
    
    std::vector<double> order = {1,2,5,10,20,50,100,200,500,1000};
    std::unordered_map<double, uint64_t> expected_buckets = {
        {1,0},{2,0},{5,0},{10,1},{20,2},{50,3},{100,4},{200,4},{500,4},{1000,5}
    };
    for (double b : order) {
        uint64_t have = 0;
        auto it = buckets.find(b);
        if (it != buckets.end()) have = it->second;
        uint64_t exp = expected_buckets[b];
        if (have != exp) { std::cerr << "bucket " << b << " expected " << exp << " got " << have << "\n"; return 1; }
    }

    
    if (std::abs(sum - 1160.0) > 1e-6) { std::cerr << "sum expected 1160 got " << sum << "\n"; return 1; }

    
    double p50_bucket = -1.0;
    for (double b : order) { uint64_t c = 0; auto it = buckets.find(b); if (it != buckets.end()) c = it->second; if (c >= 3) { p50_bucket = b; break; } }
    if (p50_bucket < 0) { std::cerr << "failed to compute p50 bucket\n"; return 1; }
    
    if (p50_bucket != 50.0) { std::cerr << "p50 expected 50 got " << p50_bucket << "\n"; return 1; }

    
    if (buckets[1000] != 5) { std::cerr << "p95 bucket (1000) expected cumulative 5 got " << buckets[1000] << "\n"; return 1; }

    
    const int threads = 4;
    const int iters = 10000;
    std::vector<std::thread> th;
    for (int t = 0; t < threads; ++t) {
        th.emplace_back([&](){
            for (int i = 0; i < iters; ++i) m.inc("/par", "POST", 201);
        });
    }
    for (auto &t : th) t.join();

    s = m.scrape();
    uint64_t par = parse_counter(s, "/par", "POST", 201);
    uint64_t expected_count = uint64_t(threads) * uint64_t(iters);
    if (par != expected_count) {
        std::cerr << "parallel counter expected " << expected_count << " got " << par << "\n";
        return 1;
    }

    std::cout << "metrics_unit ok\n";
    return 0;
}

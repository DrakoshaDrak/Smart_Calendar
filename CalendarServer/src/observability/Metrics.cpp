#include "Metrics.h"

namespace observability {

Metrics& Metrics::instance() {
    static Metrics m;
    return m;
}

Metrics::Metrics() {}

void Metrics::inc(const std::string& path, const std::string& method, int code) {
    MetricsKey k{path, method, code};
    std::lock_guard lock(mu_);
    auto it = map_.find(k);
    if (it == map_.end()) map_.emplace(k, 1);
    else it->second += 1;
}

void Metrics::observe_latency(const std::string& path, const std::string& method, double latency_ms) {
    static const std::vector<double> buckets = {1,2,5,10,20,50,100,200,500,1000,2000,5000};
    MetricsKey k{path, method, 0};
    std::lock_guard lock(mu_);
    auto it = hist_.find(k);
    if (it == hist_.end()) {
        HistData h;
        h.buckets.assign(buckets.size(), 0);
        h.sum = latency_ms;
        h.count = 1;
        for (size_t i = 0; i < buckets.size(); ++i) { if (latency_ms <= buckets[i]) { h.buckets[i] = 1; } }
        hist_.emplace(k, std::move(h));
        return;
    }
    auto& h = it->second;
    h.count += 1;
    h.sum += latency_ms;
    for (size_t i = 0; i < buckets.size(); ++i) { if (latency_ms <= buckets[i]) { h.buckets[i] += 1; } }
}

std::string Metrics::scrape() const {
    std::ostringstream ss;
    ss << "# HELP http_requests_total Total HTTP requests\n";
    ss << "# TYPE http_requests_total counter\n";
    std::lock_guard lock(mu_);
    for (const auto& p : map_) {
        ss << "http_requests_total{path=\"" << p.first.path << "\",method=\"" << p.first.method << "\",code=\"" << p.first.code << "\"} " << p.second << "\n";
    }
    ss << "# HELP http_request_duration_ms Histogram of request durations\n";
    ss << "# TYPE http_request_duration_ms histogram\n";
    static const std::vector<double> buckets = {1,2,5,10,20,50,100,200,500,1000,2000,5000};
    for (const auto& p : hist_) {
        const auto& k = p.first;
        const auto& h = p.second;
        for (size_t i = 0; i < buckets.size(); ++i) {
            ss << "http_request_duration_ms_bucket{path=\"" << k.path << "\",method=\"" << k.method << "\",le=\"" << buckets[i] << "\"} " << h.buckets[i] << "\n";
        }
        ss << "http_request_duration_ms_bucket{path=\"" << k.path << "\",method=\"" << k.method << "\",le=\"+Inf\"} " << h.count << "\n";
        ss << "http_request_duration_ms_sum{path=\"" << k.path << "\",method=\"" << k.method << "\"} " << h.sum << "\n";
        ss << "http_request_duration_ms_count{path=\"" << k.path << "\",method=\"" << k.method << "\"} " << h.count << "\n";
    }
    return ss.str();
}

} 

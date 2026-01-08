
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>
#include "cache/CacheKeys.h"

int main() {
    
    auto k1 = cache_key_events_month("cal1", 2023, 5);
    auto k2 = cache_key_events_month("cal1", 2023, 5);
    if (k1 != k2) { std::cerr << "cache_key_events_month not deterministic\n"; return 1; }

    
    if (k1.empty()) { std::cerr << "cache key empty\n"; return 1; }
    if (k1.find(' ') != std::string::npos) { std::cerr << "cache key contains space\n"; return 1; }
    if (k1.find('\n') != std::string::npos || k1.find('\r') != std::string::npos || k1.find('\t') != std::string::npos) { std::cerr << "cache key contains control char\n"; return 1; }
    if (k1.size() >= 512) { std::cerr << "cache key too long\n"; return 1; }

    
    auto ka = cache_key_events_month("calA", 2023, 5);
    auto kb = cache_key_events_month("calB", 2023, 5);
    if (ka == kb) { std::cerr << "cache keys equal for different calendar ids\n"; return 1; }

    
    auto km1 = cache_key_events_month("cal1", 2023, 5);
    auto km2 = cache_key_events_month("cal1", 2023, 6);
    if (km1 == km2) { std::cerr << "cache keys equal for different months\n"; return 1; }

    
    auto p = parse_year_month_from_iso_utc("2023-05-01T00:00:00Z");
    if (!p.has_value() || p->first != 2023 || p->second != 5) { std::cerr << "parse_year_month_from_iso_utc failed\n"; return 1; }

    
    if (parse_year_month_from_iso_utc("").has_value()) { std::cerr << "parse_year_month_from_iso_utc(\"\") should be nullopt\n"; return 1; }
    if (parse_year_month_from_iso_utc("2023-13-01T00:00:00Z").has_value()) { std::cerr << "parse_year_month_from_iso_utc(2023-13) should be nullopt\n"; return 1; }
    if (parse_year_month_from_iso_utc("not-a-date").has_value()) { std::cerr << "parse_year_month_from_iso_utc(not-a-date) should be nullopt\n"; return 1; }
    
    if (!parse_year_month_from_iso_utc("2023-05-01").has_value()) { std::cerr << "parse_year_month_from_iso_utc(YYYY-MM-DD) expected to succeed per implementation\n"; return 1; }

    
    auto touched = months_touched("2023-05-01T00:00:00Z", std::optional<std::string_view>("2023-06-01T00:00:00Z"));
    if (touched.size() != 2) { std::cerr << "months_touched expected 2 months, got=" << touched.size() << "\n"; return 1; }
    if (touched[0] != "202305" || touched[1] != "202306") { std::cerr << "months_touched months mismatch\n"; return 1; }

    
    auto touched2 = months_touched("2023-05-31T23:59:59Z", std::optional<std::string_view>("2023-06-01T00:00:00Z"));
    if (touched2.size() != 2) { std::cerr << "months_touched boundary expected 2 months, got=" << touched2.size() << "\n"; return 1; }
    if (touched2[0] != "202305" || touched2[1] != "202306") { std::cerr << "months_touched boundary months mismatch\n"; return 1; }

    
    auto touched3 = months_touched("2023-05-01T00:00:00Z", std::optional<std::string_view>());
    if (touched3.size() != 1) { std::cerr << "months_touched single expected 1 month, got=" << touched3.size() << "\n"; return 1; }
    if (touched3[0] != "202305") { std::cerr << "months_touched single month mismatch\n"; return 1; }

    
    std::unordered_set<std::string> s;
    const int N = 100;
    for (int i = 0; i < N; ++i) {
        std::string cal = "cal" + std::to_string(i);
        std::string key = cache_key_events_month(cal, 2023 + (i%5), 1 + (i%12));
        s.insert(key);
    }
    if ((int)s.size() != N) { std::cerr << "collision detected in generated keys size=" << s.size() << " expected=" << N << "\n"; return 1; }

    std::cout << "cache_keys_unit ok\n";
    return 0;
}

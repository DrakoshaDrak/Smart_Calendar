#include "CacheKeys.h"
#include <cstdio>
#include <string_view>
#include <cstdlib>
#include <string>
#include <cctype>


static bool parse_yyyy_mm_sv(std::string_view s, int& y, int& m) {
    if (s.size() < 7) return false;
    for (int i=0;i<4;++i) if (!std::isdigit((unsigned char)s[i])) return false;
    if (s[4] != '-') return false;
    if (!std::isdigit((unsigned char)s[5]) || !std::isdigit((unsigned char)s[6])) return false;
    y = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
    m = (s[5]-'0')*10 + (s[6]-'0');
    if (m < 1 || m > 12) return false;
    return true;
}

std::string cache_key_events_month(const std::string& calid, int y, int m) {
    char buf[16]; std::snprintf(buf, sizeof(buf), "%04d%02d", y, m);
    return std::string("ev:") + calid + ":" + std::string(buf);
}

std::optional<std::pair<int,int>> parse_year_month_from_iso_utc(std::string_view iso_ts) {
    int y=0,m=0; if (!parse_yyyy_mm_sv(iso_ts, y, m)) return std::nullopt; return std::make_pair(y,m);
}

std::vector<std::string> months_touched(std::string_view start_ts, const std::optional<std::string_view>& end_ts) {
    std::vector<std::string> out;
    auto p = parse_year_month_from_iso_utc(start_ts);
    if (!p.has_value()) return out;
    int y = p->first, m = p->second;
    {
        char b[8]; std::snprintf(b, sizeof(b), "%04d%02d", y, m);
        out.emplace_back(b);
    }
    if (end_ts.has_value()) {
        auto q = parse_year_month_from_iso_utc(end_ts.value());
        if (q.has_value()) {
            int y2 = q->first, m2 = q->second;
            if (y2 != y || m2 != m) {
                char b2[8]; std::snprintf(b2, sizeof(b2), "%04d%02d", y2, m2);
                out.emplace_back(b2);
            }
        }
    }
    return out;
}

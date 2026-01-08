#include "Materializer.h"
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace recurrence {

static bool parse_iso_date_time_utc(const std::string& s_in, std::tm& out_tm) {
    
    std::string s = s_in;

    
    
    if (s.size() >= 19 && s[10] == ' ') {
        s[10] = 'T';
        
        auto plus = s.find('+', 19);
        auto minus = s.find('-', 19);
        size_t tz = (plus != std::string::npos) ? plus : minus;

        if (tz != std::string::npos) {
            std::string off = s.substr(tz); 
            
            if (off == "+00" || off == "+00:00" || off == "+0000") {
                s.erase(tz);
                s.push_back('Z');
            } else {
                return false; 
            }
        } else {
            
            s.push_back('Z');
        }
    }

    
    
    auto dot = s.find('.', 19);
    if (dot != std::string::npos) {
        auto z = s.find('Z', dot);
        if (z != std::string::npos) {
            s.erase(dot, z - dot); 
        }
    }

    
    if (s.size() < 20) return false;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':') return false;
    if (s.back() != 'Z') return false;

    try {
        out_tm = {};
        out_tm.tm_year = std::stoi(s.substr(0,4)) - 1900;
        out_tm.tm_mon  = std::stoi(s.substr(5,2)) - 1;
        out_tm.tm_mday = std::stoi(s.substr(8,2));
        out_tm.tm_hour = std::stoi(s.substr(11,2));
        out_tm.tm_min  = std::stoi(s.substr(14,2));
        out_tm.tm_sec  = std::stoi(s.substr(17,2));
        return true;
    } catch(...) {
        return false;
    }
}




















std::optional<time_t> parse_iso_z(const std::string& s) {
    std::tm tm{};
    if (!parse_iso_date_time_utc(s, tm)) return std::nullopt;
#if defined(_WIN32)
    
    time_t t = _mkgmtime(&tm);
#else
    
    time_t t = timegm(&tm);
#endif
    return t;
}

std::string format_iso_z(time_t t) {
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::vector<std::pair<std::string, std::optional<std::string>>> materialize_occurrences(const std::string& base_start_iso, const std::optional<std::string>& base_end_iso, const Rule& rule, time_t window_from, time_t window_to) {
    std::vector<std::pair<std::string, std::optional<std::string>>> out;
    auto base_start_opt = parse_iso_z(base_start_iso);
    if (!base_start_opt) return out;
    time_t base_start = *base_start_opt;
    std::optional<time_t> base_end;
    if (base_end_iso.has_value()) base_end = parse_iso_z(base_end_iso.value());
    
    std::optional<time_t> duration;
    if (base_end.has_value()) duration = base_end.value() - base_start;

    
    int interval = rule.interval < 1 ? 1 : rule.interval;
    if (rule.count.has_value() && rule.count.value() <= 0) return out;

    std::optional<time_t> until_ts;
    if (rule.until_ts.has_value()) {
        until_ts = parse_iso_z(rule.until_ts.value());
        if (!until_ts) return out;
    }

    if (rule.freq != "DAILY" && rule.freq != "WEEKLY") return out;

    if (rule.freq == "DAILY") {
        
        time_t cur = base_start;
        int seen = 0; 
        while (true) {
            if (until_ts.has_value() && cur > until_ts.value()) break;
            if (rule.count.has_value() && seen >= rule.count.value()) break;
            
            if (cur >= window_from && cur < window_to) {
                out.emplace_back(format_iso_z(cur), duration.has_value() ? std::optional<std::string>(format_iso_z(cur + duration.value())) : std::nullopt);
            }
            ++seen;
            
            cur += interval * 24 * 60 * 60;
            if (cur >= window_to && !rule.count.has_value() && !until_ts.has_value()) break;
        }
        return out;
    }

    
    
    std::vector<int> weekdays;
    if (rule.byweekday.has_value() && !rule.byweekday->empty()) {
        weekdays = *rule.byweekday;
        
        weekdays.erase(std::remove_if(weekdays.begin(), weekdays.end(), [](int d){ return d < 0 || d > 6; }), weekdays.end());
        if (weekdays.empty()) return out;
    } else {
        
        std::tm tm2{};
#if defined(_WIN32)
        gmtime_s(&tm2, &base_start);
#else
        gmtime_r(&base_start, &tm2);
#endif
        int w = tm2.tm_wday; 
        int d = (w == 0) ? 6 : (w - 1);
        weekdays.push_back(d);
    }

    std::sort(weekdays.begin(), weekdays.end());
    
    std::tm bd_tm{};
#if defined(_WIN32)
    gmtime_s(&bd_tm, &base_start);
#else
    gmtime_r(&base_start, &bd_tm);
#endif
    int time_of_day = bd_tm.tm_hour * 3600 + bd_tm.tm_min * 60 + bd_tm.tm_sec;
    
    int base_w = bd_tm.tm_wday; int base_d = (base_w == 0) ? 6 : (base_w - 1); 
    time_t week0_monday_midnight = base_start - (base_d * 24 * 60 * 60) - time_of_day;

    int seen = 0;
    for (int week_i = 0;; ++week_i) {
        
        time_t week_start_midnight = week0_monday_midnight + (time_t)week_i * (time_t)rule.interval * 7 * 24 * 60 * 60;
        
        if (!rule.count.has_value() && !until_ts.has_value()) {
            
            time_t first_candidate = week_start_midnight + (time_t)weekdays.front() * 24 * 60 * 60 + time_of_day;
            if (first_candidate >= window_to) break;
        }
        for (int wd : weekdays) {
            time_t candidate = week_start_midnight + (time_t)wd * 24 * 60 * 60 + time_of_day;
            if (candidate < base_start) continue; 
            if (until_ts.has_value() && candidate > until_ts.value()) { continue; }
            
            if (candidate >= window_from && candidate < window_to) {
                out.emplace_back(format_iso_z(candidate), duration.has_value() ? std::optional<std::string>(format_iso_z(candidate + duration.value())) : std::nullopt);
            }
            ++seen;
            if (rule.count.has_value() && seen >= rule.count.value()) return out;
        }
        
        if (!rule.count.has_value() && !until_ts.has_value()) {
            time_t next_week_first = week_start_midnight + (time_t)rule.interval * 7 * 24 * 60 * 60 + (time_t)weekdays.front() * 24 * 60 * 60 + time_of_day;
            if (next_week_first >= window_to) break;
        }
    }
    return out;
}

} 

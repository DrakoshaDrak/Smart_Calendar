#pragma once
#include <string>
#include <vector>
#include <optional>

namespace recurrence {

struct Rule {
    std::string freq; 
    int interval = 1;
    std::optional<int> count;
    std::optional<std::string> until_ts; 
    std::optional<std::vector<int>> byweekday; 
};


std::optional<time_t> parse_iso_z(const std::string& s);


std::string format_iso_z(time_t t);




std::vector<std::pair<std::string, std::optional<std::string>>> materialize_occurrences(const std::string& base_start_iso, const std::optional<std::string>& base_end_iso, const Rule& rule, time_t window_from, time_t window_to);

}

#pragma once
#include <string>
#include <optional>
#include <vector>
#include <utility>
#include <string_view>
#pragma once
#include <string>
#include <optional>
#include <vector>
#include <utility>


std::string cache_key_events_month(const std::string& calid, int y, int m);


std::optional<std::pair<int,int>> parse_year_month_from_iso_utc(std::string_view iso_ts);



std::vector<std::string> months_touched(std::string_view start_ts, const std::optional<std::string_view>& end_ts);

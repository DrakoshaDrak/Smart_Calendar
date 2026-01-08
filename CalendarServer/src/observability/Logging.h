#pragma once

#include <string>
#include <unordered_map>
#include <variant>

namespace observability {

using FieldValue = std::variant<std::string, int64_t, double>;
using Fields = std::unordered_map<std::string, FieldValue>;

void log_info(const std::string& msg, const Fields& fields = {});
void log_warn(const std::string& msg, const Fields& fields = {});
void log_error(const std::string& msg, const Fields& fields = {});

void set_log_level(int level);

} 

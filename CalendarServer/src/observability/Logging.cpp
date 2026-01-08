#include "Logging.h"
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace observability {

static int g_level = 2;

void set_log_level(int level) { g_level = level; }

static int level_from_name(const std::string& name) {
    if (name == "DEBUG") return 1;
    if (name == "INFO") return 2;
    if (name == "WARN") return 3;
    return 4;
}

static int64_t now_ms() {
    using namespace std::chrono;
    return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static std::string to_string_field(const FieldValue& v) {
    if (std::holds_alternative<std::string>(v)) return std::get<std::string>(v);
    if (std::holds_alternative<int64_t>(v)) return std::to_string(std::get<int64_t>(v));
    if (std::holds_alternative<double>(v)) {
        std::ostringstream ss; ss << std::fixed << std::setprecision(3) << std::get<double>(v); return ss.str();
    }
    return "";
}
static std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

static void log_generic(int level, const std::string& lvl_name, const std::string& msg, const Fields& fields) {
    if (level < g_level) return;
    std::ostringstream ss;
    ss << '{';
    ss << "\"ts\":" << now_ms() << ',';
    ss << "\"level\":\"" << lvl_name << "\",";
    ss << "\"msg\":\"" << escape_json(msg) << "\"";
    for (const auto& p : fields) {
        ss << ",\"" << escape_json(p.first) << "\":";
        if (std::holds_alternative<std::string>(p.second)) {
            ss << '\"' << escape_json(std::get<std::string>(p.second)) << '\"';
        } else if (std::holds_alternative<int64_t>(p.second)) {
            ss << std::get<int64_t>(p.second);
        } else if (std::holds_alternative<double>(p.second)) {
            std::ostringstream tmp; tmp << std::fixed << std::setprecision(3) << std::get<double>(p.second);
            ss << tmp.str();
        }
    }
    ss << '}';
    std::cout << ss.str() << std::endl;
}

void log_info(const std::string& msg, const Fields& fields) { log_generic(2, "INFO", msg, fields); }
void log_warn(const std::string& msg, const Fields& fields) { log_generic(3, "WARN", msg, fields); }
void log_error(const std::string& msg, const Fields& fields) { log_generic(4, "ERROR", msg, fields); }

} // namespace observability

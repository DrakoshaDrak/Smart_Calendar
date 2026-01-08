
#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <string_view>
#include <limits>
#include <utility>


std::pair<bool,std::string> json_extract_string_present(const std::string& js, const std::string& key);
std::pair<bool,int64_t> json_extract_int_present(const std::string& js, const std::string& key);
std::optional<int64_t> json_extract_int_opt(const std::string& js, const std::string& key);
std::string json_escape_resp(const std::string& s);
std::string json_extract_string(const std::string& js, const std::string& key);
std::pair<bool, std::optional<std::string>> json_extract_string_opt_present(const std::string& js, const std::string& key);
std::string json_emit_int(const std::optional<std::string>& o, int64_t fallback);
std::string json_emit_int_or_null(const std::optional<std::string>& o);
std::optional<int64_t> json_parse_int_strict(const std::optional<std::string>& o);
std::string json_emit_int32(const std::optional<std::string>& o, int fallback);



inline std::optional<int64_t> parse_int64_strict_sv(std::string_view s) {
    if (s.empty()) return std::nullopt;
    size_t i = 0;
    bool neg = false;
    if (s[i] == '-') { neg = true; ++i; }
    if (i >= s.size()) return std::nullopt;

    const uint64_t maxAbs = neg ? (uint64_t(std::numeric_limits<int64_t>::max()) + 1ULL) : uint64_t(std::numeric_limits<int64_t>::max());
    uint64_t v = 0;
    for (; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < '0' || c > '9') return std::nullopt;
        uint64_t d = uint64_t(c - '0');
        if (v > (maxAbs - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }

    if (!neg) {
        if (v > uint64_t(std::numeric_limits<int64_t>::max())) return std::nullopt;
        return static_cast<int64_t>(v);
    }
    
    if (v == (uint64_t(std::numeric_limits<int64_t>::max()) + 1ULL)) return std::numeric_limits<int64_t>::min();
    return -static_cast<int64_t>(v);
}


inline std::optional<int> parse_int_strict_sv(std::string_view s) {
    if (s.empty()) return std::nullopt;

    size_t i = 0;
    bool neg = false;
    if (s[i] == '-') { neg = true; ++i; }
    if (i >= s.size()) return std::nullopt;

    const uint64_t maxAbs = neg ? (uint64_t(std::numeric_limits<int>::max()) + 1ULL) : uint64_t(std::numeric_limits<int>::max());
    uint64_t v = 0;
    for (; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < '0' || c > '9') return std::nullopt;
        uint64_t d = uint64_t(c - '0');
        if (v > (maxAbs - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }

    if (!neg) {
        if (v > uint64_t(std::numeric_limits<int>::max())) return std::nullopt;
        return static_cast<int>(v);
    }
    if (v == (uint64_t(std::numeric_limits<int>::max()) + 1ULL)) return std::numeric_limits<int>::min();
    int64_t signed_v = -static_cast<int64_t>(v);
    if (signed_v < std::numeric_limits<int>::min()) return std::nullopt;
    return static_cast<int>(signed_v);
}


inline std::optional<int> json_parse_int32_strict(const std::optional<std::string>& o) {
    if (!o.has_value() || o->empty()) return std::nullopt;
    auto p = json_parse_int_strict(o); 
    if (!p.has_value()) return std::nullopt;
    int64_t v = *p;
    if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) return std::nullopt;
    return static_cast<int>(v);
}

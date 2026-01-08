#include "Resp.h"
#include <sstream>
#include <cstdlib>

namespace cache {

std::string resp_encode(const std::vector<std::string>& args) {
    std::string out;
    out += "*" + std::to_string(args.size()) + "\r\n";
    for (const auto& a : args) {
        out += "$" + std::to_string(a.size()) + "\r\n";
        out += a + "\r\n";
    }
    return out;
}

static const char* parse_ptr(const std::string& s) { return s.c_str(); }

static std::optional<RespValue> parse_single(const std::string& buf, size_t& pos) {
    if (pos >= buf.size()) return std::nullopt;
    char t = buf[pos++];
    if (t == '+') {
        size_t e = buf.find("\r\n", pos);
        if (e == std::string::npos) return std::nullopt;
        RespValue v; v.type = RespType::SimpleString; v.str = buf.substr(pos, e - pos); pos = e + 2; return v;
    }
    if (t == '-') {
        size_t e = buf.find("\r\n", pos);
        if (e == std::string::npos) return std::nullopt;
        RespValue v; v.type = RespType::Error; v.str = buf.substr(pos, e - pos); pos = e + 2; return v;
    }
    if (t == ':') {
        size_t e = buf.find("\r\n", pos);
        if (e == std::string::npos) return std::nullopt;
        RespValue v; v.type = RespType::Integer; v.integer = std::stoll(buf.substr(pos, e - pos)); pos = e + 2; return v;
    }
    if (t == '$') {
        size_t e = buf.find("\r\n", pos);
        if (e == std::string::npos) return std::nullopt;
        int64_t len = std::stoll(buf.substr(pos, e - pos)); pos = e + 2;
        if (len == -1) { RespValue v; v.type = RespType::Null; return v; }
        if (pos + static_cast<size_t>(len) + 2 > buf.size()) return std::nullopt;
        RespValue v; v.type = RespType::BulkString; v.str = buf.substr(pos, (size_t)len); pos += (size_t)len + 2; return v;
    }
    if (t == '*') {
        size_t e = buf.find("\r\n", pos);
        if (e == std::string::npos) return std::nullopt;
        int64_t cnt = std::stoll(buf.substr(pos, e - pos)); pos = e + 2;
        if (cnt == -1) { RespValue v; v.type = RespType::Null; return v; }
        RespValue v; v.type = RespType::Array;
        for (int i = 0; i < cnt; ++i) {
            auto elem = parse_single(buf, pos);
            if (!elem.has_value()) return std::nullopt;
            v.arr.push_back(std::move(*elem));
        }
        return v;
    }
    return std::nullopt;
}

std::optional<RespValue> resp_parse(const std::string& buf) {
    size_t pos = 0;
    return parse_single(buf, pos);
}

} 

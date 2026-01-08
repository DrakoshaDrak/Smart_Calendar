
#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <string>
#include <cstdlib>
#include <chrono>
#include <utility>
#include <stdexcept>
#include <cctype>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

static inline std::string base_url() {
    const char* e = std::getenv("BASE_URL");
    if (e && e[0]) return std::string(e);
    return std::string("http://127.0.0.1:8080");
}

static inline std::pair<std::string,std::string> parse_base_url() {
    std::string b = base_url();
    size_t pos = std::string::npos;
    if (b.rfind("http://", 0) == 0) pos = 7;
    else if (b.rfind("https://", 0) == 0) {
        throw std::runtime_error("https BASE_URL not supported by test client; use http://HOST:PORT");
    } else pos = 0;
    std::string hostport = b.substr(pos);
    size_t slash = hostport.find('/');
    if (slash != std::string::npos) hostport = hostport.substr(0, slash);
    size_t colon = hostport.rfind(':');
    if (colon == std::string::npos) return {hostport, std::string("80")};
    std::string host = hostport.substr(0, colon);
    std::string port = hostport.substr(colon + 1);
    if (host.empty()) host = "127.0.0.1";
    if (port.empty()) port = "80";
    return {host, port};
}

static inline std::string json_extract_string(const std::string& js, const std::string& key) {
    
    std::string q = "\"" + key + "\"";
    size_t pos = js.find(q);
    if (pos == std::string::npos) return {};
    size_t colon = js.find(':', pos + q.size());
    if (colon == std::string::npos) return {};
    size_t i = colon + 1;
    while (i < js.size() && isspace((unsigned char)js[i])) ++i;
    if (i >= js.size()) return {};
    if (js[i] != '"') return {};
    ++i;
    std::string out;
    for (; i < js.size(); ++i) {
        char c = js[i];
        if (c == '\\') {
            if (i + 1 < js.size()) {
                char n = js[i+1];
                if (n == '\\' || n == '"') { out.push_back(n); i++; continue; }
                if (n == 'n') { out.push_back('\n'); i++; continue; }
                if (n == 'r') { out.push_back('\r'); i++; continue; }
                if (n == 't') { out.push_back('\t'); i++; continue; }
                // unknown escape -> skip backslash
                ++i; if (i < js.size()) out.push_back(js[i]); else break;
            }
        } else if (c == '"') {
            return out;
        } else {
            out.push_back(c);
        }
    }
    return {};
}
// Simple JSON int extractor (finds "key":NUMBER)
static inline int json_extract_int(const std::string& js, const std::string& key, int fallback=-1) {
    std::string q = "\"" + key + "\"";
    size_t pos = js.find(q);
    if (pos == std::string::npos) return fallback;
    size_t colon = js.find(':', pos + q.size()); if (colon == std::string::npos) return fallback;
    size_t start = colon + 1; while (start < js.size() && isspace((unsigned char)js[start])) ++start;
    size_t end = start; while (end < js.size() && (isdigit((unsigned char)js[end]) || js[end]=='-' )) ++end;
    if (end <= start) return fallback;
    try { return std::stoi(js.substr(start, end-start)); } catch(...) { return fallback; }
}

// Find calendar object by id in a JSON array body and extract the integer role field for that item
static inline int json_find_calendar_role(const std::string& body, const std::string& calId, int fallback=-1) {
    size_t pos = body.find(calId);
    if (pos == std::string::npos) return fallback;
    // search backward to find '{' that begins the containing object
    size_t obj_start = body.rfind('{', pos);
    if (obj_start == std::string::npos) obj_start = 0;
    // find closing brace
    size_t obj_end = body.find('}', pos);
    if (obj_end == std::string::npos) obj_end = body.size();
    std::string sub = body.substr(obj_start, obj_end - obj_start + 1);
    return json_extract_int(sub, "role", fallback);
}

static inline std::pair<int,std::string> request(const std::string& method, const std::string& target, const std::string& body = "", const std::string& token = "") {
    auto [host, port] = parse_base_url();
    asio::io_context ioc;
    asio::ip::tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);
    // timeouts (per operation)
    const auto op_timeout = std::chrono::seconds(5);
    // Resolve
    beast::error_code ec;
    auto const results = resolver.resolve(host, port, ec);
    if (ec) throw std::runtime_error("resolve failed for " + host + ":" + port + " -> " + ec.message());
    // Connect with timeout
    stream.expires_after(op_timeout);
    stream.connect(results, ec);
    if (ec) {
        if (ec == asio::error::timed_out) throw std::runtime_error("connect timeout " + host + ":" + port + " target=" + target);
        throw std::runtime_error("connect failed " + host + ":" + port + " -> " + ec.message());
    }
    http::request<http::string_body> req{http::verb::get, target, 11};
    if (method == "POST") req.method(http::verb::post);
    else if (method == "PATCH") req.method(http::verb::patch);
    else if (method == "DELETE") req.method(http::verb::delete_);
    else if (method == "PUT") req.method(http::verb::put);
    req.set(http::field::host, host);
    if (!body.empty()) req.set(http::field::content_type, "application/json");
    if (!token.empty()) req.set(http::field::authorization, std::string("Bearer ") + token);
    req.body() = body;
    if (!body.empty()) req.prepare_payload();

    // Write with timeout
    stream.expires_after(op_timeout);
    http::write(stream, req, ec);
    if (ec) {
        if (ec == asio::error::timed_out) throw std::runtime_error("write timeout " + host + ":" + port + " target=" + target);
        throw std::runtime_error("write failed " + host + ":" + port + " -> " + ec.message());
    }

    // Read with timeout
    beast::flat_buffer b;
    http::response<http::string_body> res;
    stream.expires_after(op_timeout);
    http::read(stream, b, res, ec);
    if (ec) {
        if (ec == asio::error::timed_out) throw std::runtime_error("read timeout " + host + ":" + port + " target=" + target);
        throw std::runtime_error("read failed " + host + ":" + port + " -> " + ec.message());
    }
    int code = res.result_int();
    std::string body_out = res.body();
    beast::error_code shut_ec;
    stream.socket().shutdown(asio::ip::tcp::socket::shutdown_both, shut_ec);
    return {code, body_out};
}

static inline std::pair<int,std::string> post_json(const std::string& target, const std::string& body, const std::string& token="") { return request("POST", target, body, token); }
static inline std::pair<int,std::string> get(const std::string& target, const std::string& token="") { return request("GET", target, "", token); }

// minimal JSON escape for constructing payloads
static inline std::string json_escape(const std::string& s) {
    std::string out; out.reserve(s.size()+4);
    for (char c : s) {
        if (c == '"') { out.push_back('\\'); out.push_back('"'); }
        else if (c == '\\') { out.push_back('\\'); out.push_back('\\'); }
        else if (c == '\n') { out.push_back('\\'); out.push_back('n'); }
        else if (c == '\r') { out.push_back('\\'); out.push_back('r'); }
        else if (c == '\t') { out.push_back('\\'); out.push_back('t'); }
        else out.push_back(c);
    }
    return out;
}

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <string>
#include <chrono>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

static std::string base_url() {
    const char* e = std::getenv("BASE_URL");
    if (e && e[0]) return std::string(e);
    return std::string("http://127.0.0.1:8080");
}

static std::pair<std::string,std::string> parse_base_url() {
    std::string b = base_url();
    size_t pos = std::string::npos;
    if (b.rfind("http://", 0) == 0) pos = 7;
    else if (b.rfind("https://", 0) == 0) pos = 8;
    else pos = 0;
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

static std::string json_extract_string(const std::string& js, const std::string& key) {
    std::string q = "\"" + key + "\"";
    size_t pos = js.find(q);
    if (pos == std::string::npos) return {};
    size_t colon = js.find(':', pos + q.size());
    if (colon == std::string::npos) return {};
    size_t start = colon + 1;
    while (start < js.size() && isspace((unsigned char)js[start])) ++start;
    if (start >= js.size() || js[start] != '"') return {};
    ++start;
    size_t end = start;
    for (; end < js.size(); ++end) { if (js[end] == '"') break; }
    if (end >= js.size()) return {};
    return js.substr(start, end - start);
}

static std::pair<int,std::string> request(const std::string& method, const std::string& target, const std::string& body = "", const std::string& token = "") {
    auto [host, port] = parse_base_url();
    asio::io_context ioc;
    asio::ip::tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port);
    beast::tcp_stream stream(ioc);
    stream.connect(results);
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
    http::write(stream, req);
    beast::flat_buffer b;
    http::response<http::string_body> res;
    http::read(stream, b, res);
    int code = res.result_int();
    std::string body_out = res.body();
    beast::error_code ec;
    stream.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    return {code, body_out};
}

static std::pair<int,std::string> post_json_status(const std::string& target, const std::string& body, const std::string& token="") {
    return request("POST", target, body, token);
}

int main() {
    try {
        std::string owner_email = "rbac_owner_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
        std::string pw = "password123";
        auto r1 = post_json_status("/auth/register", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + pw + "\"}");
        if (r1.first != 201 && r1.first != 409) { std::cerr << "owner register failed: " << r1.first << " body=" << r1.second << std::endl; return 2; }
        auto r2 = post_json_status("/auth/login", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + pw + "\"}");
        if (r2.first != 200) { std::cerr << "owner login failed: " << r2.first << std::endl; return 2; }
        std::string owner_token = json_extract_string(r2.second, "token");
        if (owner_token.empty()) { std::cerr << "no owner token" << std::endl; return 2; }
        auto rc = post_json_status("/calendars", std::string("{\"title\":\"RBAC Test Cal\"}"), owner_token);
        if (rc.first != 201) { std::cerr << "create cal failed: " << rc.first << " body=" << rc.second << std::endl; return 2; }
        std::string calid = json_extract_string(rc.second, "id");
        if (calid.empty()) { std::cerr << "no cal id" << std::endl; return 2; }

        std::string b_email = "rbac_b_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
        std::string c_email = "rbac_c_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()+1) + "@example.local";
        auto rb1 = post_json_status("/auth/register", std::string("{\"email\":\"") + b_email + "\",\"password\":\"" + pw + "\"}");
        auto rc1 = post_json_status("/auth/register", std::string("{\"email\":\"") + c_email + "\",\"password\":\"" + pw + "\"}");
        auto share_b = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + b_email + "\",\"role\":1}" , owner_token);
        if (!(share_b.first == 201 || share_b.first == 200)) { std::cerr << "owner share B failed: " << share_b.first << " body=" << share_b.second << std::endl; return 2; }
        auto login_b = post_json_status("/auth/login", std::string("{\"email\":\"") + b_email + "\",\"password\":\"" + pw + "\"}");
        if (login_b.first != 200) { std::cerr << "login B failed: " << login_b.first << std::endl; return 2; }
        std::string b_token = json_extract_string(login_b.second, "token");
        if (b_token.empty()) { std::cerr << "no b token" << std::endl; return 2; }

        auto try_promote = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + c_email + "\",\"role\":1}" , b_token);
        if (try_promote.first != 403) { std::cerr << "B promote C expected 403 got " << try_promote.first << " body=" << try_promote.second << std::endl; return 2; }
        if (try_promote.second.find("\"error\":\"forbidden\"") == std::string::npos || try_promote.second.find("only owner can assign moderator role") == std::string::npos) { std::cerr << "B promote C wrong body: " << try_promote.second << std::endl; return 2; }

        auto add_c_reader = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + c_email + "\",\"role\":0}" , b_token);
        if (!(add_c_reader.first == 201 || add_c_reader.first == 200)) { std::cerr << "B add C reader failed: " << add_c_reader.first << " body=" << add_c_reader.second << std::endl; return 2; }

        auto try_promote2 = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + c_email + "\",\"role\":1}" , b_token);
        if (try_promote2.first != 403) { std::cerr << "B promote C again expected 403 got " << try_promote2.first << " body=" << try_promote2.second << std::endl; return 2; }

        auto owner_promote = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + c_email + "\",\"role\":1}" , owner_token);
        if (!(owner_promote.first == 201 || owner_promote.first == 200)) { std::cerr << "owner promote C failed: " << owner_promote.first << " body=" << owner_promote.second << std::endl; return 2; }

        std::cout << "rbac_http_smoke ok" << std::endl;
        return 0;
    } catch (std::exception& e) {
        std::cerr << "rbac_http_smoke exception: " << e.what() << std::endl;
        return 2;
    }
}

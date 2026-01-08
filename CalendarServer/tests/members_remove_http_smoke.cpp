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
        std::string pw = "password123";
        std::string owner_email = "rm_owner_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
        auto r1 = post_json_status("/auth/register", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + pw + "\"}");
        if (r1.first != 201 && r1.first != 409) { std::cerr << "owner register failed: " << r1.first << " body=" << r1.second << std::endl; return 2; }
        auto r2 = post_json_status("/auth/login", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + pw + "\"}");
        if (r2.first != 200) { std::cerr << "owner login failed: " << r2.first << std::endl; return 2; }
        std::string owner_token = json_extract_string(r2.second, "token");
        if (owner_token.empty()) { std::cerr << "no owner token" << std::endl; return 2; }
        auto rc = post_json_status("/calendars", std::string("{\"title\":\"Remove Test Cal\"}"), owner_token);
        if (rc.first != 201) { std::cerr << "create cal failed: " << rc.first << " body=" << rc.second << std::endl; return 2; }
        std::string calid = json_extract_string(rc.second, "id");
        if (calid.empty()) { std::cerr << "no cal id" << std::endl; return 2; }

        auto make_email = [&](const std::string& prefix){ return prefix + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local"; };
        std::string b_email = make_email("rm_b_");
        std::string c_email = make_email("rm_c_");
        std::string d_email = make_email("rm_d_");

        auto reg_b = post_json_status("/auth/register", std::string("{\"email\":\"") + b_email + "\",\"password\":\"" + pw + "\"}");
        auto reg_c = post_json_status("/auth/register", std::string("{\"email\":\"") + c_email + "\",\"password\":\"" + pw + "\"}");
        auto reg_d = post_json_status("/auth/register", std::string("{\"email\":\"") + d_email + "\",\"password\":\"" + pw + "\"}");

        
        auto share_b = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + b_email + "\",\"role\":1}", owner_token);
        if (!(share_b.first == 201 || share_b.first == 200)) { std::cerr << "owner share B failed: " << share_b.first << " body=" << share_b.second << std::endl; return 2; }
        auto share_c = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + c_email + "\",\"role\":0}", owner_token);
        if (!(share_c.first == 201 || share_c.first == 200)) { std::cerr << "owner share C failed: " << share_c.first << " body=" << share_c.second << std::endl; return 2; }
        auto share_d = post_json_status(std::string("/calendars/") + calid + "/share", std::string("{\"email\":\"") + d_email + "\",\"role\":1}", owner_token);
        if (!(share_d.first == 201 || share_d.first == 200)) { std::cerr << "owner share D failed: " << share_d.first << " body=" << share_d.second << std::endl; return 2; }

        
        auto lb = post_json_status("/auth/login", std::string("{\"email\":\"") + b_email + "\",\"password\":\"" + pw + "\"}");
        auto ld = post_json_status("/auth/login", std::string("{\"email\":\"") + d_email + "\",\"password\":\"" + pw + "\"}");
        auto lc = post_json_status("/auth/login", std::string("{\"email\":\"") + c_email + "\",\"password\":\"" + pw + "\"}");
        if (lb.first != 200 || ld.first != 200 || lc.first != 200) { std::cerr << "login failed for one of users" << std::endl; return 2; }
        std::string b_token = json_extract_string(lb.second, "token");
        std::string d_token = json_extract_string(ld.second, "token");
        std::string c_token = json_extract_string(lc.second, "token");

        
        auto list_members = request("GET", std::string("/calendars/") + calid + "/members", "", owner_token);
        if (list_members.first != 200) { std::cerr << "list members failed: " << list_members.first << " body=" << list_members.second << std::endl; return 2; }
        auto find_id_by_email = [&](const std::string& body, const std::string& email)->std::string {
            size_t pos = body.find(email);
            if (pos == std::string::npos) return std::string();
            
            size_t uid_pos = body.rfind("\"user_id\":\"", pos);
            if (uid_pos == std::string::npos) return std::string();
            size_t start = uid_pos + strlen("\"user_id\":\"");
            size_t end = body.find('"', start);
            if (end == std::string::npos) return std::string();
            return body.substr(start, end - start);
        };
    std::string b_id = find_id_by_email(list_members.second, b_email);
    std::string c_id = find_id_by_email(list_members.second, c_email);
    std::string d_id = find_id_by_email(list_members.second, d_email);
    std::cout << "members list body: " << list_members.second << std::endl;
    std::cout << "parsed ids: b=" << b_id << " c=" << c_id << " d=" << d_id << std::endl;
        if (b_id.empty() || c_id.empty() || d_id.empty()) { std::cerr << "could not find member ids" << std::endl; return 2; }

        
        auto del_c_by_b = request("DELETE", std::string("/calendars/") + calid + "/members/" + c_id, "", b_token);
        if (!(del_c_by_b.first == 204)) { std::cerr << "B delete C expected 204 got " << del_c_by_b.first << " body=" << del_c_by_b.second << std::endl; return 2; }

        
        auto del_d_by_b = request("DELETE", std::string("/calendars/") + calid + "/members/" + d_id, "", b_token);
        if (del_d_by_b.first != 403) { std::cerr << "B delete D expected 403 got " << del_d_by_b.first << " body=" << del_d_by_b.second << std::endl; return 2; }

        
        auto del_d_by_owner = request("DELETE", std::string("/calendars/") + calid + "/members/" + d_id, "", owner_token);
        if (del_d_by_owner.first != 204) { std::cerr << "owner delete D expected 204 got " << del_d_by_owner.first << " body=" << del_d_by_owner.second << std::endl; return 2; }

        
        
        auto list2 = request("GET", std::string("/calendars/") + calid + "/members", "", owner_token);
        if (list2.first != 200) { std::cerr << "list members failed2: " << list2.first << std::endl; return 2; }
        std::string owner_id = find_id_by_email(list2.second, owner_email);
        if (owner_id.empty()) { std::cerr << "could not find owner id" << std::endl; return 2; }
        auto del_owner_self = request("DELETE", std::string("/calendars/") + calid + "/members/" + owner_id, "", owner_token);
        if (!(del_owner_self.first == 400 || del_owner_self.first == 403)) { std::cerr << "owner self-delete expected 400/403 got " << del_owner_self.first << " body=" << del_owner_self.second << std::endl; return 2; }

        
        auto get_by_c = request("GET", std::string("/calendars/") + calid, "", c_token);
        if (get_by_c.first != 403) { std::cerr << "deleted user C still has access: " << get_by_c.first << " body=" << get_by_c.second << std::endl; return 2; }

        std::cout << "members_remove_http_smoke ok" << std::endl;
        return 0;
    } catch (std::exception& e) {
        std::cerr << "members_remove_http_smoke exception: " << e.what() << std::endl;
        return 2;
    }
}

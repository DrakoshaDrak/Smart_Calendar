#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

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



static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
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
    if (code != 204) {
        auto ctype = res[http::field::content_type];
        if (ctype.empty() || ctype.find("application/json") == std::string::npos) {
            std::cerr << "bad content-type from " << target << " got='" << std::string(ctype) << "'" << std::endl;
        }
    }
    beast::error_code ec;
    stream.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    return {code, body_out};
}

// Raw TCP helpers for targeted tests (do not use high-level HTTP helpers)
static bool read_until_eof(asio::ip::tcp::socket& sock, std::string& out, int timeout_ms=2000) {
    boost::system::error_code ec;
    sock.non_blocking(true, ec);
    auto start = std::chrono::steady_clock::now();
    for (;;) {
        char buf[1024];
        std::size_t n = 0;
        boost::system::error_code recv_ec;
        n = sock.read_some(asio::buffer(buf), recv_ec);
        if (recv_ec) {
            if (recv_ec == asio::error::eof) {
                out.append(buf, n);
                return true;
            }
            // would block -> continue until timeout
            if (recv_ec == asio::error::would_block || recv_ec == asio::error::try_again) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() > timeout_ms) return false;
                continue;
            }
            return false;
        }
        out.append(buf, n);
        // continue until EOF
    }
}

static bool test_oversized_header() {
    auto [host, port] = parse_base_url();
    asio::io_context ioc; asio::ip::tcp::resolver resolver(ioc);
    auto results = resolver.resolve(host, port);
    asio::ip::tcp::socket sock(ioc); asio::connect(sock, results);
    // build header with a very large custom header > 8KB
    std::string big(9000, 'A');
    std::string req = "GET /me HTTP/1.1\r\nHost: example\r\nX-Big: " + big + "\r\n\r\n";
    asio::write(sock, asio::buffer(req));
    // read response line
    beast::flat_buffer b;
    http::response<http::string_body> res;
    try {
        http::read(sock, b, res);
        if (res.result_int() != 431) { std::cerr << "oversized header: expected 431 got " << res.result_int() << std::endl; sock.close(); return false; }
    } catch (std::exception& e) {
        std::cerr << "oversized header: read exception: " << e.what() << std::endl; sock.close(); return false;
    }
    // ensure socket closed by server (read should return EOF)
    std::string rest; bool eof = read_until_eof(sock, rest, 500);
    sock.close();
    if (!eof) { std::cerr << "oversized header: server did not close connection" << std::endl; return false; }
    return true;
}

static bool test_oversized_body() {
    auto [host, port] = parse_base_url();
    asio::io_context ioc; asio::ip::tcp::resolver resolver(ioc);
    auto results = resolver.resolve(host, port);
    asio::ip::tcp::socket sock(ioc); asio::connect(sock, results);
    // send a POST with Content-Length > 1MB
    std::size_t len = 1024*1024 + 1;
    std::string hdr = "POST /auth/login HTTP/1.1\r\nHost: example\r\nContent-Length: " + std::to_string(len) + "\r\nContent-Type: application/json\r\n\r\n";
    asio::write(sock, asio::buffer(hdr));
    // send body of len bytes (stream in 16KB chunks)
    const std::size_t chunk = 16*1024;
    std::string chunk_buf(chunk, 'a');
    std::size_t sent = 0;
    while (sent < len) {
        std::size_t tosend = std::min(chunk, len - sent);
        asio::write(sock, asio::buffer(chunk_buf.data(), tosend));
        sent += tosend;
    }
    beast::flat_buffer b; http::response<http::string_body> res;
    try {
        http::read(sock, b, res);
        if (res.result_int() != 413) { std::cerr << "oversized body: expected 413 got " << res.result_int() << std::endl; sock.close(); return false; }
    } catch (std::exception& e) {
        std::cerr << "oversized body: read exception: " << e.what() << std::endl; sock.close(); return false;
    }
    std::string rest; bool eof = read_until_eof(sock, rest, 500);
    sock.close();
    if (!eof) { std::cerr << "oversized body: server did not close connection" << std::endl; return false; }
    return true;
}

static bool test_slowloris_header() {
    auto [host, port] = parse_base_url();
    asio::io_context ioc; asio::ip::tcp::resolver resolver(ioc);
    auto results = resolver.resolve(host, port);
    asio::ip::tcp::socket sock(ioc); asio::connect(sock, results);
    // send partial headers (no final CRLFCRLF)
    std::string partial = "GET /me HTTP/1.1\r\nHost: example\r\nX-Test: slow";
    asio::write(sock, asio::buffer(partial));
    // wait >5s for server to close
    std::this_thread::sleep_for(std::chrono::seconds(7));
    // try reading; should be EOF or connection reset
    boost::system::error_code ec; char buf[1]; size_t n = sock.read_some(asio::buffer(buf), ec);
    sock.close();
    if (!ec) {
        std::cerr << "slowloris header: expected socket closed by server, read returned " << n << " bytes" << std::endl; return false;
    }
    return true;
}

static bool test_slow_body() {
    auto [host, port] = parse_base_url();
    asio::io_context ioc; asio::ip::tcp::resolver resolver(ioc);
    auto results = resolver.resolve(host, port);
    asio::ip::tcp::socket sock(ioc); asio::connect(sock, results);
    // send headers with Content-Length: 1000
    std::size_t len = 1000;
    std::string hdr = "POST /auth/login HTTP/1.1\r\nHost: example\r\nContent-Length: " + std::to_string(len) + "\r\nContent-Type: application/json\r\n\r\n";
    asio::write(sock, asio::buffer(hdr));
    // send a small piece of body then wait more than the 20s window
    std::string part = std::string(10, 'a'); asio::write(sock, asio::buffer(part));
    std::this_thread::sleep_for(std::chrono::seconds(22));
    // now try to read -> server should have closed connection
    boost::system::error_code ec; char buf[1]; size_t n = sock.read_some(asio::buffer(buf), ec);
    sock.close();
    if (!ec) { std::cerr << "slow body: expected socket closed by server, read returned " << n << " bytes" << std::endl; return false; }
    return true;
}

// helper wrappers
static std::pair<int,std::string> post_json_status(const std::string& target, const std::string& body, const std::string& token="") {
    return request("POST", target, body, token);
}

static std::pair<int,std::string> get_status(const std::string& target, const std::string& token="") {
    return request("GET", target, "", token);
}

int main() {
    try {
    // Early targeted integration tests for timeouts/limits
    if (!test_oversized_header()) { std::cerr << "test_oversized_header failed" << std::endl; return 2; }
    if (!test_oversized_body()) { std::cerr << "test_oversized_body failed" << std::endl; return 2; }
    if (!test_slowloris_header()) { std::cerr << "test_slowloris_header failed" << std::endl; return 2; }
    if (!test_slow_body()) { std::cerr << "test_slow_body failed" << std::endl; return 2; }

        // register owner
        std::string owner_email = "owner_test_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
        std::string owner_pw = "password123";
        auto r1 = post_json_status("/auth/register", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + owner_pw + "\"}");
        if (r1.first != 201) { std::cerr << "register owner failed: " << r1.first << " body=" << r1.second << std::endl; return 2; }
        
        auto r2 = post_json_status("/auth/login", std::string("{\"email\":\"") + owner_email + "\",\"password\":\"" + owner_pw + "\"}");
        if (r2.first != 200) { std::cerr << "login owner failed: " << r2.first << std::endl; return 2; }
        std::string token_owner = json_extract_string(r2.second, "token");
        if (token_owner.empty()) { std::cerr << "no token owner" << std::endl; return 2; }
        
        auto r3 = post_json_status("/calendars", std::string("{\"title\":\"TestCal\"}"), token_owner);
        if (r3.first != 201) { std::cerr << "create cal failed: " << r3.first << " body=" << r3.second << std::endl; return 2; }
        std::string cal_id = json_extract_string(r3.second, "id");
        if (cal_id.empty()) { std::cerr << "no cal id" << std::endl; return 2; }
        
        std::string user_email = "user_test_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "@example.local";
        auto r4 = post_json_status("/auth/register", std::string("{\"email\":\"") + user_email + "\",\"password\":\"" + owner_pw + "\"}" );
        if (r4.first != 201) { std::cerr << "register user failed: " << r4.first << std::endl; return 2; }
        auto r5 = post_json_status("/auth/login", std::string("{\"email\":\"") + user_email + "\",\"password\":\"" + owner_pw + "\"}");
        if (r5.first != 200) { std::cerr << "login user failed: " << r5.first << std::endl; return 2; }
        std::string token_user = json_extract_string(r5.second, "token");
        if (token_user.empty()) { std::cerr << "no token user" << std::endl; return 2; }
        
    std::string share_reader = std::string("{") + "\"email\":\"" + json_escape(user_email) + "\"," + "\"role\":0" + "}";
        auto r6 = post_json_status(std::string("/calendars/") + cal_id + "/share", share_reader, token_owner);
        if (r6.first != 201) { std::cerr << "share reader failed: " << r6.first << " body=" << r6.second << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id, std::string("{\"title\":\"X\"}"), token_user);
            if (pr.first != 403) { std::cerr << "reader patch expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "reader delete expected 403 got " << pr.first << std::endl; return 2; }
        }
        
    
    std::string promote_moderator = std::string("{") + "\"email\":\"" + json_escape(user_email) + "\"," + "\"role\":1" + "}";
    auto r7 = post_json_status(std::string("/calendars/") + cal_id + "/share", promote_moderator, token_owner);
    if (r7.first != 201 && r7.first != 200) { std::cerr << "promote failed: " << r7.first << " body=" << r7.second << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id, std::string("{\"title\":\"X2\"}"), token_user);
            if (pr.first != 200) { std::cerr << "moderator patch expected 200 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "moderator delete expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id, std::string(), token_owner);
            if (pr.first != 204) { std::cerr << "owner delete expected 204 got " << pr.first << std::endl; return 2; }
        }
        
        
        auto r8 = post_json_status("/calendars", std::string("{\"title\":\"EvtCal\"}"), token_owner);
        if (r8.first != 201) { std::cerr << "create cal for events failed: " << r8.first << " body=" << r8.second << std::endl; return 2; }
        std::string cal_id2 = json_extract_string(r8.second, "id"); if (cal_id2.empty()) { std::cerr << "no cal id2" << std::endl; return 2; }
        
        auto r9 = post_json_status(std::string("/calendars/") + cal_id2 + "/share", share_reader, token_owner);
        if (r9.first != 201) { std::cerr << "share reader 2 failed: " << r9.first << " body=" << r9.second << std::endl; return 2; }
        
        std::string ev_body = std::string("{\"title\":\"Meeting\",\"description\":\"Discuss\",\"start_ts\":\"2026-01-04T12:00:00Z\",\"end_ts\":\"2026-01-04T13:00:00Z\"}");
        auto re1 = post_json_status(std::string("/calendars/") + cal_id2 + "/events", ev_body, token_owner);
        if (re1.first != 201) { std::cerr << "create event failed: " << re1.first << " body=" << re1.second << std::endl; return 2; }
        std::string ev_id = json_extract_string(re1.second, "id"); if (ev_id.empty()) { std::cerr << "no ev id" << std::endl; return 2; }
        
        auto gr = get_status(std::string("/calendars/") + cal_id2 + "/events?from=2026-01-04T00:00:00Z&to=2026-01-05T00:00:00Z", token_user);
        if (gr.first != 200) { std::cerr << "reader list events failed: " << gr.first << " body=" << gr.second << std::endl; return 2; }
        if (gr.second.find(ev_id) == std::string::npos) { std::cerr << "event not found in list" << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id2 + "/events/" + ev_id, std::string("{\"title\":\"Changed\"}"), token_user);
            if (pr.first != 403) { std::cerr << "reader patch event expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id2 + "/events/" + ev_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "reader delete event expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        auto r10 = post_json_status(std::string("/calendars/") + cal_id2 + "/share", promote_moderator, token_owner);
        if (r10.first != 201 && r10.first != 200) { std::cerr << "promote failed2: " << r10.first << " body=" << r10.second << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id2 + "/events/" + ev_id, std::string("{\"title\":\"ChangedByMod\"}"), token_user);
            if (pr.first != 200) { std::cerr << "moderator patch event expected 200 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id2 + "/events/" + ev_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "moderator delete event expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id2 + "/events/" + ev_id, std::string(), token_owner);
            if (pr.first != 204) { std::cerr << "owner delete event expected 204 got " << pr.first << std::endl; return 2; }
        }

    
    auto r11 = post_json_status("/calendars", std::string("{\"title\":\"TaskCal\"}"), token_owner);
    if (r11.first != 201) { std::cerr << "create cal for tasks failed: " << r11.first << " body=" << r11.second << std::endl; return 2; }
    std::string cal_id3 = json_extract_string(r11.second, "id"); if (cal_id3.empty()) { std::cerr << "no cal id3" << std::endl; return 2; }
    auto r12 = post_json_status(std::string("/calendars/") + cal_id3 + "/share", share_reader, token_owner);
    if (r12.first != 201) { std::cerr << "share reader 3 failed: " << r12.first << " body=" << r12.second << std::endl; return 2; }
    
    std::string task_body = std::string("{\"title\":\"DoThing\",\"description\":\"Todo\"}");
    auto rt1 = post_json_status(std::string("/calendars/") + cal_id3 + "/tasks", task_body, token_owner);
        if (rt1.first != 201) { std::cerr << "create task failed: " << rt1.first << " body=" << rt1.second << std::endl; return 2; }
        std::string task_id = json_extract_string(rt1.second, "id"); if (task_id.empty()) { std::cerr << "no task id" << std::endl; return 2; }
    
    auto tr = get_status(std::string("/calendars/") + cal_id3 + "/tasks", token_user);
        if (tr.first != 200) { std::cerr << "reader list tasks failed: " << tr.first << " body=" << tr.second << std::endl; return 2; }
        if (tr.second.find(task_id) == std::string::npos) { std::cerr << "task not found in list" << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id3 + "/tasks/" + task_id, std::string("{\"title\":\"X\"}"), token_user);
            if (pr.first != 403) { std::cerr << "reader patch task expected 403 got " << pr.first << std::endl; return 2; }
        }
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id3 + "/tasks/" + task_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "reader delete task expected 403 got " << pr.first << std::endl; return 2; }
        }
    
    auto r13 = post_json_status(std::string("/calendars/") + cal_id3 + "/share", promote_moderator, token_owner);
    if (r13.first != 201 && r13.first != 200) { std::cerr << "promote failed3: " << r13.first << " body=" << r13.second << std::endl; return 2; }
        
        {
            auto pr = request("PATCH", std::string("/calendars/") + cal_id3 + "/tasks/" + task_id, std::string("{\"status\":1}"), token_user);
            if (pr.first != 200) { std::cerr << "moderator patch task expected 200 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id3 + "/tasks/" + task_id, std::string(), token_user);
            if (pr.first != 403) { std::cerr << "moderator delete task expected 403 got " << pr.first << std::endl; return 2; }
        }
        
        {
            auto pr = request("DELETE", std::string("/calendars/") + cal_id3 + "/tasks/" + task_id, std::string(), token_owner);
            if (pr.first != 204) { std::cerr << "owner delete task expected 204 got " << pr.first << std::endl; return 2; }
        }

        std::cout << "http_smoke ok" << std::endl;
        return 0;
    } catch (std::exception& e) {
        std::cerr << "http_smoke exception: " << e.what() << std::endl;
        return 2;
    }
}

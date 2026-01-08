
#include <iostream>
#include <string>
#include "net/Router.h"
#include "net/Request.h"
#include "net/Response.h"
#include <boost/beast/http.hpp>

using namespace boost::beast::http;

static Request make_request(verb m, const std::string& target) {
    Request req{m, target, 11};
    req.set(field::host, "localhost");
    req.prepare_payload();
    return req;
}

int main() {
    Router r;

    
    {
    auto req = make_request(verb::get, "/nope");
        auto res = r.route(req);
        if (res.result() != status::not_found) { std::cerr << "expected 404 for /nope, got " << res.result_int() << "\n"; return 1; }
    }

    
    r.add_route("GET", "/ping", [](const Request& req)->Response{
        Response res{status::ok, req.version()};
        res.set(field::content_type, "text/plain");
        res.body() = "pong";
        res.prepare_payload();
        return res;
    });

    
    {
    auto req = make_request(verb::post, "/ping");
        auto res = r.route(req);
        if (res.result() != status::method_not_allowed) {
            std::cerr << "expected 405 for POST /ping, got " << res.result_int() << "\n"; return 1;
        }
    }

    
    {
    auto req = make_request(verb::get, "/ping");
        auto res = r.route(req);
        if (res.result() != status::ok) { std::cerr << "expected 200 for GET /ping\n"; return 1; }
        if (res.body() != "pong") { std::cerr << "GET /ping body mismatch: " << res.body() << "\n"; return 1; }
    }

    
    
    r.add_route("GET", "/items/", [](const Request& req)->Response{
        
        Response res{status::ok, req.version()}; res.body() = ""; res.prepare_payload(); return res; });

    
    r.add_route("GET", "/items/abc", [](const Request& req)->Response{
        Response res{status::ok, req.version()}; res.body() = std::string("abc"); res.prepare_payload(); return res; });

    {
    auto req = make_request(verb::get, "/items/abc");
        auto res = r.route(req);
        if (res.result() != status::ok) { std::cerr << "expected 200 for /items/abc\n"; return 1; }
        if (res.body() != "abc") { std::cerr << "items body mismatch: " << res.body() << "\n"; return 1; }
    }

    
    r.add_route("GET", "/q?x=1", [](const Request& req)->Response{ Response res{status::ok, req.version()}; res.body() = "ok"; res.prepare_payload(); return res; });
    {
    auto req = make_request(verb::get, "/q?x=1");
        auto res = r.route(req);
        if (res.result() != status::ok) { std::cerr << "expected 200 for /q?x=1\n"; return 1; }
    }

    
    r.add_route("GET", "/a/b", [](const Request& req)->Response{ Response res{status::ok, req.version()}; res.body() = "exact"; res.prepare_payload(); return res; });
    r.add_route("GET", "/a/", [](const Request& req)->Response{ Response res{status::ok, req.version()}; res.body() = "prefix"; res.prepare_payload(); return res; });
    {
    auto req = make_request(verb::get, "/a/b");
        auto res = r.route(req);
        if (res.body() != "exact") { std::cerr << "route ordering failed, expected exact got " << res.body() << "\n"; return 1; }
    }

    std::cout << "router_unit ok\n";
    return 0;
}

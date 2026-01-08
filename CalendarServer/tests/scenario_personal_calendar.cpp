#include "http_test_util.h"
#include <iostream>
#include <chrono>

int main() {
    try {
        std::string suffix = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::string email = std::string("pc_user_") + suffix + "@example.local";
        std::string pw = "password123";
        
        auto r = post_json("/auth/register", std::string("{\"email\":\"") + json_escape(email) + "\",\"password\":\"" + pw + "\"}");
        if (r.first != 201) { std::cerr << "register failed: " << r.first << " body=" << r.second << std::endl; return 2; }
        
        auto l = post_json("/auth/login", std::string("{\"email\":\"") + json_escape(email) + "\",\"password\":\"" + pw + "\"}");
        if (l.first != 200) { std::cerr << "login failed: " << l.first << std::endl; return 2; }
        std::string token = json_extract_string(l.second, "token"); if (token.empty()) { std::cerr << "no token" << std::endl; return 2; }

        
        auto c = post_json("/calendars", std::string("{\"title\":\"A-cal-") + json_escape(suffix) + "\"}" , token);
        if (c.first != 201) { std::cerr << "create cal failed: " << c.first << std::endl; return 2; }
        std::string calId = json_extract_string(c.second, "id"); if (calId.empty()) { std::cerr << "no cal id" << std::endl; return 2; }

        
    auto list = get("/calendars", token);
    if (list.first != 200) { std::cerr << "list cals failed: " << list.first << std::endl; return 2; }
    if (list.second.find(calId) == std::string::npos) { std::cerr << "cal not in list" << std::endl; return 2; }
    int role = json_find_calendar_role(list.second, calId, -1);
    if (role != 2) { std::cerr << "expected role=2 owner got=" << role << " body=" << list.second << std::endl; return 2; }

        
        std::string start = "2026-02-10T10:00:00Z";
        std::string end = "2026-02-10T11:00:00Z";
        std::string evbody = std::string("{\"title\":\"Ev-") + json_escape(suffix) + "\",\"description\":\"desc\",\"start_ts\":\"" + start + "\",\"end_ts\":\"" + end + "\"}";
        auto evr = post_json(std::string("/calendars/") + calId + "/events", evbody, token);
        if (evr.first != 201) { std::cerr << "create event failed: " << evr.first << " body=" << evr.second << std::endl; return 2; }
        std::string evId = json_extract_string(evr.second, "id"); if (evId.empty()) { std::cerr << "no ev id" << std::endl; return 2; }

        
        auto gl = get(std::string("/calendars/") + calId + "/events?from=2026-02-01T00:00:00Z&to=2026-03-01T00:00:00Z", token);
        if (gl.first != 200) { std::cerr << "get events failed: " << gl.first << std::endl; return 2; }
        if (gl.second.find(evId) == std::string::npos) { std::cerr << "event not listed" << std::endl; return 2; }

        
        auto patch = request("PATCH", std::string("/calendars/") + calId + "/events/" + evId, std::string("{\"title\":\"Updated\",\"description\":\"New\"}"), token);
        if (patch.first != 200) { std::cerr << "patch failed: " << patch.first << std::endl; return 2; }
        
        auto gl2 = get(std::string("/calendars/") + calId + "/events?from=2026-02-01T00:00:00Z&to=2026-03-01T00:00:00Z", token);
        if (gl2.first != 200) { std::cerr << "get events2 failed: " << gl2.first << std::endl; return 2; }
        if (gl2.second.find("Updated") == std::string::npos) { std::cerr << "patch not visible" << std::endl; return 2; }

        
        auto del = request("DELETE", std::string("/calendars/") + calId + "/events/" + evId, std::string(), token);
        if (del.first != 204) { std::cerr << "delete event expected 204 got " << del.first << std::endl; return 2; }

        
        auto gl3 = get(std::string("/calendars/") + calId + "/events?from=2026-02-01T00:00:00Z&to=2026-03-01T00:00:00Z", token);
        if (gl3.first != 200) { std::cerr << "get events3 failed: " << gl3.first << std::endl; return 2; }
        if (gl3.second.find(evId) != std::string::npos) { std::cerr << "event still present after delete" << std::endl; return 2; }

        std::cout << "scenario_personal_calendar ok" << std::endl;
        return 0;
    } catch (std::exception& e) { std::cerr << "exception: " << e.what() << std::endl; return 2; }
}

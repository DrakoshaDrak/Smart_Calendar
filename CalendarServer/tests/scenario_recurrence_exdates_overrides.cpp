#include "http_test_util.h"
#include <iostream>
#include <chrono>

int main() {
    try {
        std::string sfx = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::string email = std::string("rec_user_") + sfx + "@example.local";
        std::string pw = "password123";
        auto r = post_json("/auth/register", std::string("{\"email\":\"") + json_escape(email) + "\",\"password\":\"" + pw + "\"}");
        if (r.first != 201) { std::cerr << "register failed: " << r.first << std::endl; return 2; }
        auto l = post_json("/auth/login", std::string("{\"email\":\"") + json_escape(email) + "\",\"password\":\"" + pw + "\"}");
        if (l.first != 200) { std::cerr << "login failed: " << l.first << std::endl; return 2; }
        std::string token = json_extract_string(l.second, "token"); if (token.empty()) { std::cerr << "no token" << std::endl; return 2; }

        auto c = post_json("/calendars", std::string("{\"title\":\"RecCal-") + json_escape(sfx) + "\"}" , token);
        if (c.first != 201) { std::cerr << "create cal failed: " << c.first << std::endl; return 2; }
        std::string calId = json_extract_string(c.second, "id");

        
        std::string evbody = std::string("{\"title\":\"Daily-") + json_escape(sfx) + "\",\"start_ts\":\"2026-04-01T09:00:00Z\",\"recurrence\":{\"freq\":\"DAILY\",\"interval\":1,\"count\":5}}";
        auto evr = post_json(std::string("/calendars/") + calId + "/events", evbody, token);
        if (evr.first != 201) { std::cerr << "create recurring event failed: " << evr.first << " body=" << evr.second << std::endl; return 2; }
        std::string rule_id = json_extract_string(evr.second, "recurrence_rule_id");
        if (rule_id.empty()) {
            
            
        }

    
    auto gl = get(std::string("/calendars/") + calId + "/events?from=2026-04-01T00:00:00Z&to=2026-05-01T00:00:00Z", token);
    if (gl.first != 200) { std::cerr << "list occ failed: " << gl.first << " body=" << gl.second << std::endl; return 2; }
    
    int count = 0; size_t pos = 0;
    const std::string needle = "\"start_ts\":\"2026-04-";
    while ((pos = gl.second.find(needle, pos)) != std::string::npos) { ++count; pos += needle.size(); }
    if (count < 5) { std::cerr << "expected >=5 occurrences got " << count << " body=" << gl.second << std::endl; return 2; }

    
    if (rule_id.empty()) rule_id = json_extract_string(gl.second, "recurrence_rule_id");
        if (rule_id.empty()) {
            
            
            std::cerr << "could not determine rule_id; response=" << gl.second << std::endl; return 2;
        }

        
        auto ex = post_json(std::string("/recurrence/") + rule_id + "/exdates", std::string("{\"date\":\"2026-04-03\"}"), token);
        if (ex.first != 200) { std::cerr << "add exdate failed: " << ex.first << " body=" << ex.second << std::endl; return 2; }
        
        auto gl2 = get(std::string("/calendars/") + calId + "/events?from=2026-04-01T00:00:00Z&to=2026-05-01T00:00:00Z", token);
        if (gl2.first != 200) { std::cerr << "list occ2 failed: " << gl2.first << std::endl; return 2; }
    int count2 = 0; pos = 0; 
    while ((pos = gl2.second.find(needle, pos)) != std::string::npos) { ++count2; pos += needle.size(); }
    if (count2 != count - 1) { std::cerr << "exdate did not reduce occurrences as expected: before=" << count << " after=" << count2 << " body=" << gl2.second << std::endl; return 2; }

        
        std::string original = "2026-04-04T09:00:00Z";
        std::string newstart = "2026-04-10T10:00:00Z";
        auto ov = request("PATCH", std::string("/recurrence/") + rule_id + "/occurrence", std::string("{\"original_start_ts\":\"") + original + "\",\"new_start_ts\":\"" + newstart + "\",\"title\":\"moved\"}" , token);
        if (ov.first != 200) { std::cerr << "occurrence patch failed: " << ov.first << " body=" << ov.second << std::endl; return 2; }

        
        auto gl3 = get(std::string("/calendars/") + calId + "/events?from=2026-04-01T00:00:00Z&to=2026-05-01T00:00:00Z", token);
        if (gl3.first != 200) { std::cerr << "list occ3 failed: " << gl3.first << std::endl; return 2; }
        if (gl3.second.find(original) != std::string::npos) { std::cerr << "original occurrence still present" << std::endl; return 2; }
        if (gl3.second.find(newstart) == std::string::npos) { std::cerr << "moved occurrence not found at new start" << std::endl; return 2; }
        if (gl3.second.find("moved") == std::string::npos) { std::cerr << "title change not visible" << std::endl; return 2; }

        std::cout << "scenario_recurrence_exdates_overrides ok" << std::endl;
        return 0;
    } catch (std::exception& e) { std::cerr << "exception: " << e.what() << std::endl; return 2; }
}

#include "http_test_util.h"
#include <iostream>
#include <chrono>
#include <cstring>

int main() {
    try {
        std::string sfx = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::string a = std::string("share_a_") + sfx + "@example.local";
        std::string b = std::string("share_b_") + sfx + "@example.local";
        std::string pw = "password123";
        
        auto ra = post_json("/auth/register", std::string("{\"email\":\"") + json_escape(a) + "\",\"password\":\"" + pw + "\"}");
        if (ra.first != 201) { std::cerr << "register A failed: " << ra.first << std::endl; return 2; }
        auto rb = post_json("/auth/register", std::string("{\"email\":\"") + json_escape(b) + "\",\"password\":\"" + pw + "\"}");
        if (rb.first != 201) { std::cerr << "register B failed: " << rb.first << std::endl; return 2; }
        
        auto la = post_json("/auth/login", std::string("{\"email\":\"") + json_escape(a) + "\",\"password\":\"" + pw + "\"}");
        auto lb = post_json("/auth/login", std::string("{\"email\":\"") + json_escape(b) + "\",\"password\":\"" + pw + "\"}");
        if (la.first != 200 || lb.first != 200) { std::cerr << "login failed" << std::endl; return 2; }
        std::string ta = json_extract_string(la.second, "token");
        std::string tb = json_extract_string(lb.second, "token");
        if (ta.empty() || tb.empty()) { std::cerr << "missing token" << std::endl; return 2; }

        
        auto c = post_json("/calendars", std::string("{\"title\":\"ShareCal-") + json_escape(sfx) + "\"}" , ta);
        if (c.first != 201) { std::cerr << "create cal failed: " << c.first << std::endl; return 2; }
        std::string calId = json_extract_string(c.second, "id");

        
    auto share = post_json(std::string("/calendars/") + calId + "/share",
                   std::string("{\"email\":\"") + json_escape(b) + "\",\"role\":0}",
                   ta);
    if (!(share.first == 201 || share.first == 200)) { std::cerr << "share failed: " << share.first << " body=" << share.second << std::endl; return 2; }

        
        auto listb = get("/calendars", tb);
        if (listb.first != 200) { std::cerr << "B list failed: " << listb.first << std::endl; return 2; }
        if (listb.second.find(calId) == std::string::npos) { std::cerr << "B does not see calendar" << std::endl; return 2; }
    int roleb = json_find_calendar_role(listb.second, calId, -1);
    if (roleb != 0) { std::cerr << "expected B role=0 got=" << roleb << " body=" << listb.second << std::endl; return 2; }

        
        auto ev = post_json(std::string("/calendars/") + calId + "/events", std::string("{\"title\":\"X\",\"start_ts\":\"2026-03-01T10:00:00Z\"}"), tb);
        if (ev.first != 403) { std::cerr << "B create event expected 403 got " << ev.first << std::endl; return 2; }

        
    auto promote = post_json(std::string("/calendars/") + calId + "/share",
                 std::string("{\"email\":\"") + json_escape(b) + "\",\"role\":1}",
                 ta);
    if (!(promote.first == 200 || promote.first == 201)) { std::cerr << "promote failed: " << promote.first << " body=" << promote.second << std::endl; return 2; }

        
        auto ev2 = post_json(std::string("/calendars/") + calId + "/events", std::string("{\"title\":\"ByB\",\"start_ts\":\"2026-03-02T10:00:00Z\"}"), tb);
        if (ev2.first != 201) { std::cerr << "B create event expected 201 got " << ev2.first << " body=" << ev2.second << std::endl; return 2; }
        std::string evId = json_extract_string(ev2.second, "id");

        
        
    auto members = get(std::string("/calendars/") + calId + "/members", ta);
    if (members.first != 200) { std::cerr << "members list failed: " << members.first << " body=" << members.second << std::endl; return 2; }
    
    size_t pos = members.second.find(b);
    if (pos == std::string::npos) { std::cerr << "members listing doesn't contain B" << std::endl; return 2; }
    size_t uid_pos = members.second.rfind("\"user_id\":\"", pos);
    if (uid_pos == std::string::npos) { std::cerr << "could not parse user_id" << std::endl; return 2; }
    size_t start = uid_pos + std::string("\"user_id\":\"").size(); size_t end = members.second.find('"', start);
    if (end == std::string::npos || end <= start) { std::cerr << "could not parse user_id bounds" << std::endl; return 2; }
    std::string b_id = members.second.substr(start, end - start);

        auto del = request("DELETE", std::string("/calendars/") + calId + "/members/" + b_id, std::string(), ta);
        if (del.first != 204) { std::cerr << "owner remove member expected 204 got " << del.first << std::endl; return 2; }

        
        auto byb = get(std::string("/calendars/") + calId, tb);
        if (!(byb.first == 403 || byb.first == 404)) { std::cerr << "after removal B access expected 403/404 got " << byb.first << std::endl; return 2; }

        std::cout << "scenario_sharing_rbac ok" << std::endl;
        return 0;
    } catch (std::exception& e) { std::cerr << "exception: " << e.what() << std::endl; return 2; }
}

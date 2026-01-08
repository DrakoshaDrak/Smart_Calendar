
#include <iostream>
#include <string>
#include <optional>
#include <limits>
#include "net/MiniJson.h"

int main() {
    
    auto e1 = json_escape_resp("abc");
    if (e1.find("abc") == std::string::npos) { std::cerr << "json_escape_resp lost plain text\n"; return 1; }
    auto e2 = json_escape_resp("a\"b");
    if (e2.find("\\\"") == std::string::npos) { std::cerr << "json_escape_resp did not escape quote\n"; return 1; }
    auto e3 = json_escape_resp("a\\b");
    if (e3.find("\\\\") == std::string::npos) { std::cerr << "json_escape_resp did not escape backslash\n"; return 1; }
    auto e4 = json_escape_resp("\n\t\r");
    if (e4.find("\\n") == std::string::npos || e4.find("\\t") == std::string::npos || e4.find("\\r") == std::string::npos) { std::cerr << "json_escape_resp did not escape control chars\n"; return 1; }
    auto e5 = json_escape_resp("привет");
    if (e5.empty()) { std::cerr << "json_escape_resp empty for unicode\n"; return 1; }

    // json_extract_string_present / json_extract_string
    {
        auto pr = json_extract_string_present("{\"a\":\"b\"}", "a");
        if (!pr.first) { std::cerr << "json_extract_string_present missing key 'a'\n"; return 1; }
        if (pr.second != "b") { std::cerr << "json_extract_string_present wrong value: " << pr.second << "\n"; return 1; }
    }
    {
        auto s = json_extract_string("{\"a\":\"b\"}", "a");
        if (s != "b") { std::cerr << "json_extract_string wrong value\n"; return 1; }
        auto s2 = json_extract_string("{}", "nope");
        if (!s2.empty()) { std::cerr << "json_extract_string expected empty for missing key\n"; return 1; }
    }
    
    try {
        auto pr = json_extract_string_present("{\"a\":123}", "a");
        
        if (pr.first && !pr.second.empty()) { std::cerr << "json_extract_string_present accepted numeric as string\n"; return 1; }
    } catch (...) {}

    
    try {
        auto pi = json_extract_int_present("{\"n\":42}", "n");
        if (!pi.first || pi.second != 42) { std::cerr << "json_extract_int_present failed to parse 42\n"; return 1; }
    } catch (...) { std::cerr << "json_extract_int_present threw on valid int\n"; return 1; }

    auto oi = json_extract_int_opt("{\"n\":42}", "n");
    if (!oi.has_value() || *oi != 42) { std::cerr << "json_extract_int_opt failed\n"; return 1; }

    
    try {
        auto big = json_extract_int_opt(std::string("{\"n\":999999999999}"), "n");
        (void)big;
    } catch (...) {}

    
    try { auto s = json_extract_string("", "a"); if (!s.empty()) { std::cerr << "empty json unexpected non-empty\n"; return 1; } } catch(...) { std::cerr << "json_extract_string threw on empty\n"; return 1; }
    try { auto s = json_extract_string("{", "a"); (void)s; } catch(...) {}
    try { auto s = json_extract_string("[]", "a"); (void)s; } catch(...) {}
    try { auto s = json_extract_string("{a:1}", "a"); (void)s; } catch(...) {}

    std::cout << "minijson_unit ok\n";
    return 0;
}

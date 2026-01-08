#include <cassert>
#include <iostream>
#include <string>
#include "net/MiniJson.h"

static void ok_val(const std::string& js, const std::string& key, const std::string& expected) {
    auto p = json_extract_string_opt_present(js, key);
    assert(p.first);
    assert(p.second.has_value());
    assert(p.second.value() == expected);
}

static void ok_null(const std::string& js, const std::string& key) {
    auto p = json_extract_string_opt_present(js, key);
    assert(p.first);
    assert(!p.second.has_value());
}

static void ok_absent(const std::string& js, const std::string& key) {
    auto p = json_extract_string_opt_present(js, key);
    assert(!p.first);
}

static void must_throw(const std::string& js, const std::string& key) {
    try {
        (void)json_extract_string_opt_present(js, key);
        assert(false && "expected throw");
    } catch (...) {
    }
}

int main() {
    
    ok_val("{\"k\":\"a\"}", "k", "a");
    ok_val("{ \"k\" : \"abc\" }", "k", "abc");

    
    ok_val("{\"k\":\"a\\n\"}", "k", std::string("a\n"));
    ok_val("{\"k\":\"a\\r\"}", "k", std::string("a\r"));
    ok_val("{\"k\":\"a\\t\"}", "k", std::string("a\t"));
        ok_val("{\"k\":\"\\\"\"}", "k", std::string("\""));
    ok_val("{\"k\":\"\\\\\\\\\"}", "k", std::string("\\"));

    // present/absent/null semantics
    ok_null("{\"k\":null}", "k");
    ok_absent("{}", "k");
    ok_absent("{\"other\":\"x\"}", "k");

    
    ok_val("{\"kk\":\"x\",\"k\":\"y\"}", "k", "y");
    ok_val("{\"k\":\"y\",\"kk\":\"x\"}", "k", "y");

    
    ok_val("{\"arr\":[\"a\",\"b\"],\"k\":\"v\"}", "k", "v");

    
    must_throw("{\"k\":123}", "k");
    must_throw("{\"k\":true}", "k");
    must_throw("{\"k\":{}}", "k");
    must_throw("{\"k\":[]}", "k");

    
    must_throw("{\"k\":\"abc}", "k");
        must_throw("{\"k\":\"\\\"}", "k"); 

    
    must_throw("{\"k\":\"\\u1234\"}", "k");
    must_throw("{\"k\":\"\\b\"}", "k");
    must_throw("{\"k\":\"\\f\"}", "k");
    must_throw("{\"k\":\"\\/\"}", "k");
    must_throw("{\"k\":\"\\x\"}", "k");

    std::cout << "json_parse_strings ok\n";
    return 0;
}

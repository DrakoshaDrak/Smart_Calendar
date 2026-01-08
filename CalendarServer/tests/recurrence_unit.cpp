#include "../src/recurrence/Materializer.h"
#include <iostream>
#include <vector>

using namespace recurrence;

int main() {
    
    Rule r1; r1.freq = "DAILY"; r1.interval = 1; r1.count = 3;
    auto occs1 = materialize_occurrences("2026-01-01T10:00:00Z", std::nullopt, r1, 1609459200 , 1893456000 );
    
    if (occs1.size() < 3) { std::cerr << "DAILY count produced less than 3 occurrences: " << occs1.size() << std::endl; return 1; }
    if (occs1[0].first != "2026-01-01T10:00:00Z") { std::cerr << "first mismatch " << occs1[0].first << std::endl; return 1; }
    if (occs1[1].first != "2026-01-02T10:00:00Z") { std::cerr << "second mismatch " << occs1[1].first << std::endl; return 1; }
    if (occs1[2].first != "2026-01-03T10:00:00Z") { std::cerr << "third mismatch " << occs1[2].first << std::endl; return 1; }

    
    Rule r2 = r1;
    time_t wf = 1641350400; 
    auto occs2 = materialize_occurrences("2026-01-01T10:00:00Z", std::nullopt, r2, 1893456000 , 1893459600 );
    if (!occs2.empty()) { std::cerr << "expected empty as window after count but got " << occs2.size() << std::endl; return 1; }

    
    Rule r3; r3.freq = "WEEKLY"; r3.interval = 1; r3.byweekday = std::vector<int>{0,2}; 
    auto occs3 = materialize_occurrences("2026-01-01T10:00:00Z", std::nullopt, r3, 0, 1893456000);
    if (occs3.size() < 2) { std::cerr << "weekly produced less than 2 occurrences" << std::endl; return 1; }
    
    bool foundMon=false, foundWed=false;
    for (size_t i=0;i<occs3.size() && i<6;++i) {
        if (occs3[i].first == "2026-01-05T10:00:00Z") foundMon = true;
        if (occs3[i].first == "2026-01-07T10:00:00Z") foundWed = true;
    }
    if (!foundMon || !foundWed) { std::cerr << "weekly weekdays not found" << std::endl; return 1; }

    std::cout << "recurrence_unit ok" << std::endl;
    return 0;
}

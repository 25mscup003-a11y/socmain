#include "ajnat/health_monitor.h"

#include <iostream>
#include <string>

int main() {
    const std::string value = ajnat::KernelCapabilitiesJson();
    const bool valid = value.size() > 2 && value.front() == '{' && value.back() == '}'
            && value.find("\"kernel_version\"") != std::string::npos
            && value.find("\"selinux_enforcing\"") != std::string::npos
            && value.find("\"ebpf_loaded\":false") != std::string::npos;
    if (!valid) {
        std::cerr << "FAIL: malformed capability report: " << value << '\n';
        return 1;
    }
    std::cout << "health_monitor_test: PASS\n";
    return 0;
}

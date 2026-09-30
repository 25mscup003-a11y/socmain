#pragma once

#include <cstdint>
#include <string>

namespace ajnat {

struct Event {
    std::string id;
    std::string type;
    std::string subtype;
    std::string payload_json;
    std::int64_t timestamp_ms;
};

std::string JsonEscape(const std::string& value);
std::string EventJson(const Event& event);
std::int64_t NowMs();

}  // namespace ajnat

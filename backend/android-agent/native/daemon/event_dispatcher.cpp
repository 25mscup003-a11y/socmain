#include "ajnat/event_dispatcher.h"

#include <chrono>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <utility>
#include <cstdio>

namespace ajnat {
namespace {

bool LooksLikeJsonObject(const std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return first != std::string::npos && last != std::string::npos
            && value[first] == '{' && value[last] == '}';
}

}  // namespace

std::int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (unsigned char character : value) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(character) << std::dec;
                } else {
                    output << character;
                }
        }
    }
    return output.str();
}

std::string EventJson(const Event& event) {
    std::ostringstream output;
    output << "{\"event_id\":\"" << JsonEscape(event.id)
           << "\",\"event_type\":\"" << JsonEscape(event.type)
           << "\",\"event_subtype\":\"" << JsonEscape(event.subtype)
           << "\",\"event_time\":" << event.timestamp_ms
           << ",\"source\":\"ajnatd\",\"payload\":"
           << (event.payload_json.empty() ? "{}" : event.payload_json) << "}";
    return output.str();
}

EventDispatcher::EventDispatcher(std::size_t capacity, std::string spool_path)
    : capacity_(capacity), spool_path_(std::move(spool_path)) {
    Load();
}

void EventDispatcher::Push(Event event) {
    if (event.id.empty() || event.id.size() > 256 || event.type.empty()
            || event.type.size() > 64 || event.subtype.size() > 128
            || event.payload_json.size() > 64 * 1024
            || !LooksLikeJsonObject(event.payload_json.empty() ? "{}" : event.payload_json)) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++dropped_;
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string encoded = EventJson(event);
    bool trimmed = false;
    if (queue_.size() >= capacity_) {
        queue_.pop_front();
        ++dropped_;
        trimmed = true;
    }
    queue_.push_back(encoded);
    if (trimmed) Rewrite();
    else Append(encoded);
}

std::string EventDispatcher::PeekJson(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t count = std::min(limit, queue_.size());
    std::ostringstream output;
    output << '[';
    for (std::size_t index = 0; index < count; ++index) {
        if (index) output << ',';
        output << queue_[index];
    }
    output << ']';
    return output.str();
}

void EventDispatcher::Acknowledge(std::size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::size_t index = 0; index < count && !queue_.empty(); ++index) queue_.pop_front();
    Rewrite();
}

std::size_t EventDispatcher::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

std::uint64_t EventDispatcher::Dropped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

void EventDispatcher::Load() {
    std::ifstream input(spool_path_);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line.size() > 64 * 1024 || !LooksLikeJsonObject(line)) {
            ++dropped_;
            continue;
        }
        if (queue_.size() >= capacity_) {
            queue_.pop_front();
            ++dropped_;
        }
        queue_.push_back(line);
    }
}

void EventDispatcher::Append(const std::string& encoded) {
    std::ofstream output(spool_path_, std::ios::app);
    if (output) output << encoded << '\n';
}

void EventDispatcher::Rewrite() {
    const std::string temporary = spool_path_ + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output) return;
        for (const std::string& encoded : queue_) output << encoded << '\n';
        output.flush();
        if (!output) return;
    }
    std::rename(temporary.c_str(), spool_path_.c_str());
}

}  // namespace ajnat

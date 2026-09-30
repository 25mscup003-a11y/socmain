#pragma once

#include "ajnat/event.h"

#include <cstddef>
#include <deque>
#include <mutex>
#include <string>

namespace ajnat {

class EventDispatcher {
  public:
    EventDispatcher(std::size_t capacity, std::string spool_path);
    void Push(Event event);
    std::string PeekJson(std::size_t limit) const;
    void Acknowledge(std::size_t count);
    std::size_t Size() const;
    std::uint64_t Dropped() const;

  private:
    void Load();
    void Append(const std::string& encoded);
    void Rewrite();
    const std::size_t capacity_;
    const std::string spool_path_;
    mutable std::mutex mutex_;
    std::deque<std::string> queue_;
    std::uint64_t dropped_ = 0;
};

}  // namespace ajnat

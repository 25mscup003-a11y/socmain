#pragma once

#include "ajnat/event_dispatcher.h"

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ajnat {

class CollectorManager {
  public:
    explicit CollectorManager(EventDispatcher* dispatcher);
    ~CollectorManager();
    void Start();
    void Stop();

  private:
    struct ProcessInfo {
        std::string name;
        int uid;
        int ppid;
    };

    void Run();
    void ScanProcesses(bool emit_changes);
    void ScanNetwork(bool emit_changes);
    void PollNetlink();
    Event ProcessEvent(const std::string& subtype, int pid, const std::string& name,
                       int uid, int ppid) const;

    EventDispatcher* dispatcher_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::unordered_map<int, ProcessInfo> processes_;
    std::unordered_set<std::string> sockets_;
    std::uint64_t sequence_ = 0;
    int netlink_fd_ = -1;
};

}  // namespace ajnat

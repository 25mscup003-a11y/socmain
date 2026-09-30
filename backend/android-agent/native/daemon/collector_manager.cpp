#include "ajnat/collector_manager.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

namespace ajnat {
namespace {

bool IsPid(const char* value) {
    if (value == nullptr || *value == '\0') return false;
    for (const char* cursor = value; *cursor; ++cursor) {
        if (!std::isdigit(static_cast<unsigned char>(*cursor))) return false;
    }
    return true;
}

bool ReadProcess(int pid, std::string* name, int* uid, int* ppid) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    if (!status) return false;
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("Name:", 0) == 0) *name = line.substr(line.find_first_not_of(" \t", 5));
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream input(line.substr(4));
            input >> *uid;
        }
        if (line.rfind("PPid:", 0) == 0) {
            std::istringstream input(line.substr(5));
            input >> *ppid;
        }
    }
    return !name->empty();
}

std::string DecodeIpv4(const std::string& encoded) {
    if (encoded.size() != 8) return "";
    unsigned long value = 0;
    try { value = std::stoul(encoded, nullptr, 16); } catch (...) { return ""; }
    std::ostringstream output;
    output << (value & 0xff) << '.' << ((value >> 8) & 0xff) << '.'
           << ((value >> 16) & 0xff) << '.' << ((value >> 24) & 0xff);
    return output.str();
}

bool ParseEndpoint(const std::string& encoded, std::string* ip, unsigned int* port) {
    const std::size_t separator = encoded.find(':');
    if (separator == std::string::npos) return false;
    *ip = DecodeIpv4(encoded.substr(0, separator));
    try { *port = std::stoul(encoded.substr(separator + 1), nullptr, 16); } catch (...) { return false; }
    return !ip->empty();
}

}  // namespace

CollectorManager::CollectorManager(EventDispatcher* dispatcher) : dispatcher_(dispatcher) {}

CollectorManager::~CollectorManager() {
    Stop();
}

void CollectorManager::Start() {
    if (running_.exchange(true)) return;
    netlink_fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (netlink_fd_ >= 0) {
        sockaddr_nl address {};
        address.nl_family = AF_NETLINK;
        address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
        if (bind(netlink_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            close(netlink_fd_);
            netlink_fd_ = -1;
        }
    }
    ScanProcesses(false);
    ScanNetwork(false);
    worker_ = std::thread(&CollectorManager::Run, this);
}

void CollectorManager::Stop() {
    if (!running_.exchange(false)) return;
    if (worker_.joinable()) worker_.join();
    if (netlink_fd_ >= 0) close(netlink_fd_);
    netlink_fd_ = -1;
}

void CollectorManager::Run() {
    unsigned int tick = 0;
    while (running_) {
        PollNetlink();
        ScanProcesses(true);
        if ((tick++ % 6) == 0) ScanNetwork(true);
        for (int i = 0; i < 10 && running_; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

Event CollectorManager::ProcessEvent(const std::string& subtype, int pid, const std::string& name,
                                     int uid, int ppid) const {
    const auto now = NowMs();
    std::ostringstream payload;
    payload << "{\"pid\":" << pid << ",\"uid\":" << uid << ",\"ppid\":" << ppid
            << ",\"process_name\":\"" << JsonEscape(name) << "\"}";
    return {"ajnatd-process-" + std::to_string(pid) + "-" + subtype + "-" + std::to_string(now),
            "process", subtype, payload.str(), now};
}

void CollectorManager::ScanProcesses(bool emit_changes) {
    std::unordered_map<int, ProcessInfo> current;
    DIR* directory = opendir("/proc");
    if (directory == nullptr) return;
    while (dirent* entry = readdir(directory)) {
        if (!IsPid(entry->d_name) || current.size() >= 4096) continue;
        const int pid = std::atoi(entry->d_name);
        std::string name;
        int uid = -1;
        int ppid = -1;
        if (!ReadProcess(pid, &name, &uid, &ppid)) continue;
        current.emplace(pid, ProcessInfo{name, uid, ppid});
        const auto previous = processes_.find(pid);
        if (emit_changes && (previous == processes_.end() || previous->second.name != name)) {
            if (previous != processes_.end()) {
                dispatcher_->Push(ProcessEvent("exit", pid, previous->second.name,
                                               previous->second.uid, previous->second.ppid));
            }
            dispatcher_->Push(ProcessEvent("start", pid, name, uid, ppid));
        }
    }
    closedir(directory);
    if (emit_changes) {
        for (const auto& previous : processes_) {
            if (current.find(previous.first) == current.end()) {
                dispatcher_->Push(ProcessEvent("exit", previous.first, previous.second.name,
                                               previous.second.uid, previous.second.ppid));
            }
        }
    }
    processes_.swap(current);
}

void CollectorManager::ScanNetwork(bool emit_changes) {
    std::unordered_set<std::string> current;
    for (const char* protocol : {"tcp", "udp"}) {
        std::ifstream input(std::string("/proc/net/") + protocol);
        std::string line;
        std::getline(input, line);
        while (std::getline(input, line) && current.size() < 4096) {
            std::istringstream fields(line);
            std::string slot, local, remote, state, queue, timer;
            unsigned int retransmit = 0;
            int uid = -1;
            if (!(fields >> slot >> local >> remote >> state >> queue >> timer >> retransmit >> uid)) continue;
            const std::string key = std::string(protocol) + ":" + local + ":" + remote + ":" + std::to_string(uid);
            current.insert(key);
            if (!emit_changes || sockets_.find(key) != sockets_.end()) continue;
            std::string source_ip, destination_ip;
            unsigned int source_port = 0, destination_port = 0;
            if (!ParseEndpoint(local, &source_ip, &source_port) || !ParseEndpoint(remote, &destination_ip, &destination_port)) continue;
            const auto now = NowMs();
            std::ostringstream payload;
            payload << "{\"protocol\":\"" << protocol << "\",\"src_ip\":\"" << source_ip
                    << "\",\"dst_ip\":\"" << destination_ip << "\",\"src_port\":" << source_port
                    << ",\"dst_port\":" << destination_port << ",\"uid\":" << uid
                    << ",\"direction\":\"unknown\"}";
            dispatcher_->Push({"ajnatd-network-" + std::to_string(++sequence_) + "-" + std::to_string(now),
                               "network", "socket_observed", payload.str(), now});
        }
    }
    sockets_.swap(current);
}

void CollectorManager::PollNetlink() {
    if (netlink_fd_ < 0) return;
    pollfd descriptor {netlink_fd_, POLLIN, 0};
    if (poll(&descriptor, 1, 0) <= 0 || !(descriptor.revents & POLLIN)) return;
    char buffer[8192];
    const ssize_t length = recv(netlink_fd_, buffer, sizeof(buffer), 0);
    if (length <= 0) return;
    int remaining = static_cast<int>(length);
    for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer);
         NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
        const char* subtype = nullptr;
        if (header->nlmsg_type == RTM_NEWLINK) subtype = "link_change";
        else if (header->nlmsg_type == RTM_DELLINK) subtype = "link_removed";
        else if (header->nlmsg_type == RTM_NEWADDR || header->nlmsg_type == RTM_DELADDR) subtype = "address_change";
        else if (header->nlmsg_type == RTM_NEWROUTE || header->nlmsg_type == RTM_DELROUTE) subtype = "route_change";
        if (subtype == nullptr) continue;
        const auto now = NowMs();
        dispatcher_->Push({"ajnatd-netlink-" + std::to_string(++sequence_) + "-" + std::to_string(now),
                           "network", subtype, "{\"source\":\"netlink_route\"}", now});
    }
}

}  // namespace ajnat

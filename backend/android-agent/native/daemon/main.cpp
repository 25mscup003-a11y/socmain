#include "ajnat/collector_manager.h"
#include "ajnat/event_dispatcher.h"
#include "ajnat/health_monitor.h"

#include <android-base/logging.h>
#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

bool AuthorizedPeer(int fd) {
    ucred credentials {};
    socklen_t credential_size = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credential_size) != 0) return false;
    if (credentials.pid <= 0 || credentials.uid <= 0) return false;

    char context[256] = {};
    socklen_t context_size = sizeof(context);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, context, &context_size) != 0) return false;
    const std::string peer(context, strnlen(context, sizeof(context)));
    const std::string expected = "u:r:ajnat_app:s0";
    return peer == expected || peer.rfind(expected + ":", 0) == 0;
}

std::string ReadCommand(int fd) {
    char buffer[129] = {};
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    if (count <= 0 || count > 128) return "";
    std::string command(buffer, static_cast<std::size_t>(count));
    command.erase(std::remove(command.begin(), command.end(), '\r'), command.end());
    command.erase(std::remove(command.begin(), command.end(), '\n'), command.end());
    return command;
}

void WriteAll(int fd, const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ssize_t written = send(fd, value.data() + offset, value.size() - offset, MSG_NOSIGNAL);
        if (written <= 0) return;
        offset += static_cast<std::size_t>(written);
    }
}

}  // namespace

int main(int argc, char** argv) {
    (void)argc;
    android::base::InitLogging(argv, android::base::KernelLogger);
    const int server = android_get_control_socket("ajnatd");
    if (server < 0) {
        LOG(ERROR) << "ajnatd init control socket unavailable: " << std::strerror(errno);
        return EXIT_FAILURE;
    }
    if (listen(server, 8) != 0) {
        LOG(ERROR) << "ajnatd listen failed: " << std::strerror(errno);
        return EXIT_FAILURE;
    }

    ajnat::EventDispatcher dispatcher(4096, "/data/misc/ajnat/native-events.ndjson");
    ajnat::CollectorManager collectors(&dispatcher);
    collectors.Start();
    LOG(INFO) << "ajnatd started with SELinux-enforced local IPC";

    for (;;) {
        const int client = accept4(server, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) continue;
            LOG(ERROR) << "ajnatd accept failed: " << std::strerror(errno);
            break;
        }
        timeval timeout {2, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (!AuthorizedPeer(client)) {
            WriteAll(client, "{\"ok\":false,\"error\":\"unauthorized_peer\"}\n");
            close(client);
            continue;
        }
        const std::string command = ReadCommand(client);
        if (command == "PING") {
            WriteAll(client, "{\"ok\":true}\n");
        } else if (command == "CAPABILITIES") {
            WriteAll(client, "{\"ok\":true,\"capabilities\":" + ajnat::KernelCapabilitiesJson()
                    + ",\"queue_depth\":" + std::to_string(dispatcher.Size())
                    + ",\"dropped\":" + std::to_string(dispatcher.Dropped()) + "}\n");
        } else if (command.rfind("PEEK ", 0) == 0) {
            char* end = nullptr;
            const long requested = std::strtol(command.c_str() + 5, &end, 10);
            if (end == command.c_str() + 5 || *end != '\0' || requested < 1 || requested > 100) {
                WriteAll(client, "{\"ok\":false,\"error\":\"invalid_limit\"}\n");
            } else {
                WriteAll(client, "{\"ok\":true,\"events\":"
                        + dispatcher.PeekJson(static_cast<std::size_t>(requested)) + "}\n");
            }
        } else if (command.rfind("ACKCOUNT ", 0) == 0) {
            char* end = nullptr;
            const long count = std::strtol(command.c_str() + 9, &end, 10);
            if (end == command.c_str() + 9 || *end != '\0' || count < 0 || count > 100) {
                WriteAll(client, "{\"ok\":false,\"error\":\"invalid_count\"}\n");
            } else {
                dispatcher.Acknowledge(static_cast<std::size_t>(count));
                WriteAll(client, "{\"ok\":true}\n");
            }
        } else {
            WriteAll(client, "{\"ok\":false,\"error\":\"unknown_command\"}\n");
        }
        close(client);
    }

    collectors.Stop();
    return EXIT_FAILURE;
}

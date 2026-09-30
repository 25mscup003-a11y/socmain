#include "ajnat/event_dispatcher.h"

#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "FAIL: " << message << '\n';
    return false;
}

}  // namespace

int main() {
    char path[] = "/tmp/ajnatd-dispatcher-test-XXXXXX";
    const int descriptor = mkstemp(path);
    if (descriptor < 0) return 2;
    close(descriptor);

    bool ok = true;
    {
        ajnat::EventDispatcher queue(2, path);
        queue.Push({"one", "process", "start", "{\"name\":\"a\\\"b\"}", 1});
        queue.Push({"two", "network", "connect", "{}", 2});
        queue.Push({"invalid", "network", "connect", "not-json", 2});
        queue.Push({"three", "file", "modify", "{}", 3});
        ok &= Expect(queue.Size() == 2, "bounded queue must retain two events");
        ok &= Expect(queue.Dropped() == 2, "queue must count invalid and capacity-dropped events");
        const std::string peek = queue.PeekJson(10);
        ok &= Expect(peek.find("\"one\"") == std::string::npos, "oldest event must be trimmed");
        ok &= Expect(peek.find("\"two\"") != std::string::npos, "second event must remain");
        queue.Acknowledge(1);
    }
    {
        ajnat::EventDispatcher recovered(2, path);
        ok &= Expect(recovered.Size() == 1, "unacknowledged event must recover after restart");
        ok &= Expect(recovered.PeekJson(1).find("\"three\"") != std::string::npos,
                     "recovered event must preserve ordering");
        recovered.Acknowledge(1);
        ok &= Expect(recovered.Size() == 0, "ACK must delete the persisted event");
    }
    std::remove(path);
    std::remove((std::string(path) + ".tmp").c_str());
    if (ok) std::cout << "event_dispatcher_test: PASS\n";
    return ok ? 0 : 1;
}

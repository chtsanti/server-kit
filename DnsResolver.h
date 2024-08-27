#ifndef __DNSRESOLVER_H
#define __DNSRESOLVER_H

#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

#include "EventLoop.h"
#include "mem.h"

class NoteDnsResolverAnswer {
public:
    NoteDnsResolverAnswer(const std::string &s) : server(s) {}
    ~NoteDnsResolverAnswer() {
        delete addresses;
    }
    void answer(std::vector<struct sockaddr_storage> *addr, bool isfinal) {
        assert(addresses == nullptr);
        addresses = addr;
        finalAnswer = isfinal;
    }
    std::string server;
    std::vector<struct sockaddr_storage> *addresses = nullptr;
    bool finalAnswer = true;
};

template <class OBJ>
class CallNoteDnsResolved: public CallJob<OBJ>, public NoteDnsResolverAnswer {
public:
    CallNoteDnsResolved(OBJ *client, const std::string &srv): CallJob<OBJ>(client), NoteDnsResolverAnswer(srv) {}
    MEMPOOL_DECLARE(CallNoteDnsResolved)
    virtual void call() {
        this->obj->noteAddresses(server, addresses, finalAnswer);
        this->_allowMoreCalls = !finalAnswer;
        delete addresses;
        addresses = nullptr;
    }
};

class DnsResolver {
public:
    class Request {
    public:
        ~Request() {}
        MEMPOOL_DECLARE(DnsResolver::Request)
        void printOutRequest();
        std::string server;
        AsyncCall *call;
        struct timespec start = {0, 0};
        uint64_t inQueue = 0;
        uint64_t firstResponse = 0;
        uint64_t finalResponse = 0;
        int cached = false;
    };
    class Response {
    public:
        ~Response() {
            delete addresses;
        }
        MEMPOOL_DECLARE(DnsResolver::Response)
        std::string server;
        AsyncCall *call = nullptr;
        std::vector<struct sockaddr_storage> *addresses = nullptr;
        bool isFinal = false;
    };

    DnsResolver(int eventNotifyFd): notifyFd(eventNotifyFd) {}
    void resolve(Request *req);
    void run();

    int notifyFd;
public:
    static void Init();
    static void Shutdown();
    static void RunResolved();
    static void ResolveName(const std::string &name, AsyncCall *call);
    static void DumpDebugInfo();
    static int eFD;
    static  std::queue<Request *> REQUESTS;
    static  std::queue<Response *> RESPONSES;
    static std::mutex REQUESTS_MTX;
    static std::condition_variable_any REQUESTS_CND;
    static std::mutex RESPONSES_MTX;
    static bool SHUTDOWN;
    static std::vector<std::thread> THREADS;
    // stats:
    static uint64_t requestsCnt;
    static uint64_t responsesCnt;
};

#endif

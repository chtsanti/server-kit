#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/eventfd.h>
#include "DnsResolver.h"
#include "EventLoop.h"
#include "LocalCache.h"

#include "utils.h"

int DnsResolver::eFD = -1;
std::queue<DnsResolver::Request *> DnsResolver::REQUESTS;
std::queue<DnsResolver::Response *> DnsResolver::RESPONSES;
std::mutex DnsResolver::REQUESTS_MTX;
std::condition_variable_any DnsResolver::REQUESTS_CND;
std::mutex DnsResolver::RESPONSES_MTX;
std::vector<std::thread> DnsResolver::THREADS;
bool DnsResolver::SHUTDOWN = false;
uint64_t DnsResolver::requestsCnt = 0;
uint64_t DnsResolver::responsesCnt = 0;

std::vector<struct sockaddr_storage> *DnsResolveCacheDuplicator(std::vector<struct sockaddr_storage> *v)
{
    if (!v)
        return nullptr;
    auto caching = new std::vector<struct sockaddr_storage>;
    caching->insert(caching->end(), v->begin(), v->end());
    return caching;
}

void DnsResolveCacheDeletor(std::vector<struct sockaddr_storage> *v)
{
    delete v;
}

static LocalCache<std::vector<struct sockaddr_storage> *, DnsResolveCacheDuplicator, DnsResolveCacheDeletor> DnsResolverCache("DnsResolveCache", 120);

MEMPOOL_IMPLEMENT2(DnsResolver, Response)
MEMPOOL_IMPLEMENT2(DnsResolver, Request)

// This is runs in worker threads:
void DnsResolver::run()
{
    int queuedRequests = 0;
    while(!SHUTDOWN) {
        REQUESTS_MTX.lock();
        if (REQUESTS.empty()) {
            REQUESTS_CND.wait(REQUESTS_MTX);
        }
        queuedRequests = REQUESTS.size();
        Request *req = nullptr;
        if (!REQUESTS.empty()) {
            req = REQUESTS.front();
            REQUESTS.pop();
        }
        REQUESTS_MTX.unlock();
        DEBUG(7, "Requests in queue:" << std::dec << queuedRequests);
        if (req) {
            struct timespec reqTime;
            clock_gettime(CLOCK_REALTIME, &reqTime);
            req->inQueue = CLOCK_TIME_DIFF(reqTime, req->start);
            resolve(req);
            delete req;
        }
    }
}

std::vector<struct sockaddr_storage> *host_get_address(const char *servername)
{

    struct addrinfo hints, *res, *r;
    //struct sockaddr_storage *tmpaddr = nullptr;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = 0;
    if ((ret = getaddrinfo(servername, NULL, &hints, &res)) != 0) {
        DEBUG(3, "Error getting addrinfo for " << servername << ":" << gai_strerror(ret));
        return NULL;
    }
    int ipv6_count = 0, ipv4_count = 0;
    std::vector<struct sockaddr_storage> *v = new std::vector<struct sockaddr_storage>;
    v->reserve(32);
    for (r = res; r != NULL; r = r->ai_next) {
        if (r->ai_family == AF_INET) ipv4_count++;
        else if (r->ai_family == AF_INET6) ipv6_count++;
        else {
            DEBUG(2, "No supported address family " << res->ai_family << " for server " << servername);
            continue;// Do not add it.
        }
        v->resize(v->size() + 1);
        assert(r->ai_addrlen <= sizeof(struct sockaddr_storage));
        memcpy(&v->back(), r->ai_addr, r->ai_addrlen);
    }

    freeaddrinfo(res);
    DEBUG(5, v->size() << " addresses (" << ipv4_count << " ipv4  " << ipv6_count << " ipv6) found for server " << servername);
    return v;
}

void DnsResolver::resolve(Request *req)
{
    assert(req);
    std::vector<struct sockaddr_storage> *addresses =  nullptr;
    if ((addresses = DnsResolverCache.get(req->server)) != nullptr) {
        req->cached = true;
    } else {
        addresses = host_get_address(req->server.c_str());
        if (addresses)
            DnsResolverCache.store(req->server, addresses);
    }
    Response *resp = new Response;
    resp->server = req->server;
    resp->call = req->call;
    resp->addresses = addresses;
    resp->isFinal = true;
    RESPONSES_MTX.lock();
    RESPONSES.push(resp);
    responsesCnt++;
    RESPONSES_MTX.unlock();
    uint64_t u = 1;
    ssize_t ret = 0;
    do {
        ret = write(notifyFd, (void *)&u, sizeof(u));
    } while(ret == -1 && errno == EINTR);

    if (ret < 0) {
        DEBUG(1, "DnsResolver, write to eventFd  error: " << print_errno(errno));
        // assert(ret && !"DnsResolver write to eventFd  error");
    } else {
        DEBUG(5, "Written " << ret << " bytes to resolver notifier fd:" << notifyFd);
    }
    struct timespec reqTime;
    clock_gettime(CLOCK_REALTIME, &reqTime);
    req->firstResponse = CLOCK_TIME_DIFF(reqTime, req->start);
    req->finalResponse = req->firstResponse;
    // if (isFinal)
    req->printOutRequest();
}

void DnsResolver::RunResolved()
{
    RESPONSES_MTX.lock();
    while(!RESPONSES.empty()) {
        Response *resp = RESPONSES.front();
        RESPONSES.pop();

        assert(resp->call);
        auto answer = dynamic_cast<NoteDnsResolverAnswer *>(resp->call);
        assert(answer);
        assert(answer->server == resp->server);
        answer->answer(resp->addresses, resp->isFinal);
        resp->addresses = nullptr;
        AsyncCall::Schedule(resp->call);
        resp->call = nullptr;
        delete resp;
    }
    RESPONSES_MTX.unlock();
}

void DnsResolver::ResolveName(const std::string &name, AsyncCall *call)
{
    Request *r = new Request;
    r->server = name;
    r->call = call;
    clock_gettime(CLOCK_REALTIME, &r->start);
    REQUESTS_MTX.lock();
    requestsCnt++;
    REQUESTS.push(r);
    REQUESTS_MTX.unlock();
    REQUESTS_CND.notify_one();
}

// Worker threads:
void do_thread_loop(DnsResolver *resolver)
{
    resolver->run();
    delete resolver;
}

// This is a callback run on event-loop thread:
void DnsResolverNoteNameResolved(evutil_socket_t eFD, short event, void *arg)
{
    uint64_t ret;
    assert(eFD == DnsResolver::eFD);
    ssize_t result = 0;
    do {
        result = read(eFD, &ret, sizeof(ret));
    } while(result == -1 && errno == EINTR);
    // assert(result >= 0 && "DnsResolverNoteNameResolved error");
    DEBUG(5, "Eventfd: "<< eFD << " returns: " << ret);
    DnsResolver::RunResolved();
}

int DnsResolverThreads = 8;
int DnsResolverCacheTTL = -1;

void DnsResolver::Init()
{
    if (DnsResolverCacheTTL > 0)
        DnsResolverCache.ttl = DnsResolverCacheTTL;
    eFD = eventfd(0, 0);
    EventLoopRegisterPersistentFD(eFD, DnsResolverNoteNameResolved);
    for(int i = 0; i < DnsResolverThreads; ++i) {
        DnsResolver *resolver = new DnsResolver(eFD);
        std::thread th(do_thread_loop, resolver);
        THREADS.push_back(std::move(th));
    }
}

void DnsResolver::Shutdown()
{
    SHUTDOWN = 1;
    int repeat = 5;
    while(repeat) {
        REQUESTS_CND.notify_all();
        repeat --;
        usleep(1000);
    }
    while(!THREADS.empty()) {
        std::thread &th = THREADS.back();
        th.join();
        THREADS.pop_back();
    }
    close(eFD);
}

void DnsResolver::Request::printOutRequest()
{
    DEBUG(5, "DnsResolver::Request, server:" << server
//          << " client:" << client
          << std::dec
          << " inQueue:" << inQueue
          << " firstResponse:" << firstResponse
          << " finalResponse:" << finalResponse
          << " cached:" << cached
        );
}

void DnsResolver::DumpDebugInfo()
{
    DEBUG(1, "DNS requests: " << requestsCnt << " Responses: " << responsesCnt);
    DEBUG(1, "DNS Cache, ttl: " << DnsResolverCache.ttl <<
          " StoredItems: " << DnsResolverCache.storedItems <<
          " Searches: " << DnsResolverCache.searches <<
          " Hits: " << DnsResolverCache.hits <<
          " Stores: " << DnsResolverCache.stores <<
          " Removed: " << DnsResolverCache.removed
        );
}

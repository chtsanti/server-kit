#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "EventLoop.h"
#include "Connection.h"
#include "DnsResolver.h"
#include "utils.h"

bool SHUTDOWN = false;
struct event_base *EventBase = nullptr;
bool EventLoopStarted = false;
int PORT = 3128;

struct timespec &CurrentTime()
{
    // TODO: check if it can be computed in event loop
    // to avoid recompute for each message.
    static thread_local struct timespec t;
    clock_gettime (CLOCK_REALTIME, &t);
    return t;
}

void IoParams::update(int fd, short ev)
{
    assert(conn->fd == fd);
    if (ev & EV_READ) {
        assert(conn->flags.read_pending);
        conn->flags.read_pending = false;
    }
    if (ev & EV_WRITE) {
        assert(conn->flags.write_pending);
        conn->flags.write_pending = false;
    }
    events = ev;
}

void Call::callWrapper()
{
    if (isCanceled) {
        DEBUG(3, "Will not call the " << name << " call because: " << isCanceled);
        return;
    }
    call();
    finish();
}

void Call::DoCall(evutil_socket_t fd, short events, void *arg)
{
    Call *call = (Call *)arg;
    if (!dynamic_cast<Call *>(call)) {
        FAIL("someone schedule a NULL callback?");
        return;
    }
    if (!call->name) {
        FAIL("unnamed call? Check for eventloop, or memory corruption bugs");
        assert(call->name);
    }
    bool deleteAfterUse = !call->_allowMoreCalls;
    call->updateFlags(fd, events);
    call->callWrapper(); // May delete call
    if (deleteAfterUse)
        delete call;
}

void AsyncCall::updateFlags(int fd, short events)
{
    if (events == EV_TIMEOUT) {
        DEBUG(4, "AsyncCall " << this->name << "  timed out\n");
        return;
    }
    assert(events == 0);
}

void do_accept(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    assert(base == EventBase);
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr*)&ss, &slen);
    if (fd < 0) { // XXXX eagain??
        DEBUG(1, "accept error:" << print_errno(errno));
    } else {
        evutil_make_socket_nonblocking(fd);
        Connection conn(fd, &ss);
        //JobObject *handler = new JobObjectKid(conn);
        //handler->start();
    }
}

void run_once(evutil_socket_t listener, short event, void *arg)
{
    DEBUG(6, "Run ONCE!");
    struct event *once = (struct event *)arg;
    event_free(once);
}

void signal_shutdown(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    assert(base == EventBase);
    SHUTDOWN = true;
    event_base_loopbreak(EventBase);
}

std::mutex EventLoopMtx;

void EventLoopRegisterPersistentFD(int fd, void (*callback)(evutil_socket_t eFD, short event, void *arg))
{
    assert(!EventLoopStarted);
    assert(EventBase);
    EventLoopMtx.lock();
    struct event *anEvent = event_new(EventBase, fd, EV_READ|EV_PERSIST, callback, nullptr);
    event_add(anEvent, NULL);

    EventLoopMtx.unlock();
}

void EventLoopRegisterTimer(void (*callback)(evutil_socket_t eFD, short event, void *arg), int secsPeriod)
{
    assert(!EventLoopStarted);
    assert(EventBase);
    struct timeval timeout = { .tv_sec = secsPeriod, .tv_usec = 0 };
    EventLoopMtx.lock();
    struct event *anEvent = event_new(EventBase, -1, EV_PERSIST, callback, nullptr);
    event_add(anEvent, &timeout);
    EventLoopMtx.unlock();
}

//The following is not enough to stop running jobs
// With a way we need to jobq::shutdown active jobs
static int event_base_close_sockets_cb(const struct event_base *, const struct event *ev, void *)
{
    if ((event_get_events(ev) & (EV_READ | EV_WRITE | EV_TIMEOUT)) == 0)
        return 0;

    int fd;
    if ((fd = event_get_fd(ev)) > 0) {
        close(fd);
    }
    return 0;
}

static void EventLoopCloseSockets(struct event_base *base)
{
#if EVENT__NUMERIC_VERSION > 0x02010000
    event_base_foreach_event(base, event_base_close_sockets_cb, nullptr);
#endif
}

void EventLoopInit()
{
    EventBase = event_base_new();
    assert(EventBase);
}

void EventLoopRun(void)
{
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event *listener_event;
    assert(EventBase);

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(PORT);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    evutil_make_socket_nonblocking(listener);

    {
        int one = 1;
        // setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    }

    if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return;
    }

    if (listen(listener, 1024) < 0) {
        perror("listen");
        return;
    }

    EventLoopMtx.lock();
    listener_event = event_new(EventBase, listener, EV_READ|EV_PERSIST, do_accept, (void*)EventBase);
    assert(listener_event);
    struct event *int_signal_event = nullptr;
    int_signal_event = event_new(EventBase, SIGINT, EV_SIGNAL|EV_PERSIST, signal_shutdown, (void*)EventBase);
    struct event *term_signal_event = nullptr;
    term_signal_event = event_new(EventBase, SIGTERM, EV_SIGNAL|EV_PERSIST, signal_shutdown, (void*)EventBase);
    event_add(listener_event, NULL);
    event_add(term_signal_event, NULL);
    event_add(int_signal_event, NULL);
    EventLoopMtx.unlock();
    EventLoopStarted = true;
    int ret = event_base_dispatch(EventBase);
    DEBUG(5, "Event loop returned: " << ret);
    EventLoopCloseSockets(EventBase);
    int loops = 5;
    while(loops > 0) {
        DEBUG(7, "EventLoop after closed sockets");
        event_base_loop(EventBase, EVLOOP_ONCE | EVLOOP_NONBLOCK);
        usleep(500000);
        loops--;
    }
}

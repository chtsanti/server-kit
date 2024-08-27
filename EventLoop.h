#ifndef EVENTLOOP_H
#define EVENTLOOP_H

#include "Debug.h"

#include <time.h>
#include <event2/event.h>

#include <cassert>
#include <iostream>

extern bool SHUTDOWN;
extern struct event_base *EventBase;

struct timespec &CurrentTime();

inline std::ostream &operator << (std::ostream &os, const struct timespec &t) {
    os << std::dec << t.tv_sec << "." << t.tv_nsec/1000;
    return os;
}

void EventLoopInit();
void EventLoopRun();
// The following should be called before event loop is started
void EventLoopRegisterPersistentFD(int fd, void (*callback)(evutil_socket_t eFD, short event, void *arg));
void EventLoopRegisterTimer(void (*callback)(evutil_socket_t eFD, short event, void *arg), int secsPeriod);

class Call {
public:
    Call(const char *n)  : name(n) {}
    virtual ~Call(){};
    void cancel(const char *reason) {isCanceled = reason;};
    void callWrapper();

    virtual void call() = 0;
    virtual void finish() = 0;
    virtual void updateFlags(int fd, short events) = 0;
public:
    const char *name;
    const char *isCanceled = nullptr;
    bool _allowMoreCalls = false;

public:
    static void DoCall(evutil_socket_t fd, short events, void *arg);
};

class JobObject {
public:
    virtual const char *myname() const {return "JobObject";}
    virtual void start() = 0;
    virtual bool done() = 0;
    virtual void shutdown() = 0;
    virtual ~JobObject() {};
public:
    static void CheckFinished(JobObject *job) {
        assert(job);
        if (job->done() || SHUTDOWN) {
            job->shutdown();
            DEBUG(2, job->myname() << "  " << job << " complete its job, destruct");
            delete job;
            return;
        }
    }
};

class Connection;
class IoParams {
public:
    IoParams(Connection *c): conn(c), events(0) {}
    void update(int fd, short events);
public:
    Connection *conn;
    short events = 0; //updated on each call
};

template<class COMM_OBJ> class IoCallJobT: public Call {
public:
    IoCallJobT(Connection *c, COMM_OBJ *commObj, void (COMM_OBJ::*method)(const Connection *, short)):
        Call(typeid(commObj).name()),
        ioParams(c),
        obj(commObj),
        aCall(method)
        { _allowMoreCalls = true; }

    virtual void call() override {
        (obj->*aCall)(ioParams.conn, ioParams.events);
    }
    virtual void finish() override {
        JobObject::CheckFinished(obj);
    }
    void updateFlags(int fd, short events) override {
        ioParams.update(fd, events);
    }
public:
    IoParams ioParams;
    COMM_OBJ *obj;
    void (COMM_OBJ::*aCall)(const Connection *, short);
};

class AsyncCall: public Call {
public:
    AsyncCall(const char *n)  : Call(n) {}
    virtual ~AsyncCall() { if (event) event_free(event);}
    virtual void updateFlags(int fd, short events) override;

    // Not implemented:
    // virtual void call() = 0;
    // virtual void finish() = 0;

public:
    struct event *event = nullptr;

public:
    static void Schedule(AsyncCall *c);
    static void ScheduleAfter(AsyncCall *c, const struct timeval &tv);
    template<class OBJ> static AsyncCall *ScheduleJobCall(OBJ *o, void (OBJ::*method)());
    template<class OBJ, class P1, class P2> static AsyncCall *ScheduleJobCall2(OBJ *o, void (OBJ::*method)(P1, P2));
    template<class OBJ> static AsyncCall *ScheduleJobCallAfter(OBJ *o, void (OBJ::*method)(), const struct timeval &tv);
};

template<class OBJ> class CallJob: public AsyncCall {
public:
    CallJob(OBJ *o): AsyncCall(typeid(o).name()), obj(o) {}
    // Not implemented:
    // virtual void call() = 0;

    virtual void finish() override {
        JobObject::CheckFinished(obj);
    }
    OBJ *obj;
};

template<class OBJ> class CallJobT0: public CallJob<OBJ> {
public:
    CallJobT0(OBJ *o, void (OBJ::*m)()) : CallJob<OBJ>(o), aCall(m) {}
    virtual void call() final {
        (this->obj->*aCall)();
    }
public:
    void (OBJ::*aCall)();
};

template<class OBJ, class P1> class CallJobT1: public CallJob<OBJ> {
public:
    CallJobT1(OBJ *o, void (OBJ::*m)(P1), P1 anArg1) : CallJob<OBJ>(o), aCall(m), arg1(anArg1) {}
    virtual void call() final {
        (this->obj->*aCall)(arg1);
    }
public:
    P1 arg1;
    void (OBJ::*aCall)(P1);
};

template<class OBJ, class P1, class P2> class CallJobT2: public CallJob<OBJ> {
public:
    CallJobT2(OBJ *o, void (OBJ::*m)(P1 , P2), P1 anArg1, P2 anArg2) : CallJob<OBJ>(o), aCall(m), arg1(anArg1), arg2(anArg2) {}
    virtual void call() final {
        (this->obj->*aCall)(arg1, arg2);
    }
public:
    P1 arg1;
    P2 arg2;
    void (OBJ::*aCall)(P1, P2);
};

inline void AsyncCall::Schedule(AsyncCall *c)
{
    c->event =  event_new(EventBase, -1, 0, Call::DoCall,  c);
    event_add(c->event, nullptr);
    event_active(c->event, 0, 0);
}

inline void AsyncCall::ScheduleAfter(AsyncCall *c, const struct timeval &tv)
{
    c->event =  event_new(EventBase, -1, 0, Call::DoCall,  c);
    event_add(c->event, &tv);
}

template<class OBJ> AsyncCall *AsyncCall::ScheduleJobCall(OBJ *o, void (OBJ::*method)())
{
    AsyncCall *c = new CallJobT0<OBJ>(o, method);
    AsyncCall::Schedule(c);
    return c;
}

template<class OBJ> AsyncCall *AsyncCall::ScheduleJobCallAfter(OBJ *o, void (OBJ::*method)(), const struct timeval &tv)
{
    AsyncCall *c = new CallJobT0<OBJ>(o, method);
    AsyncCall::ScheduleAfter(c, tv);
    return c;
}

#endif

#ifndef __TLSACCEPTOR_H
#define __TLSACCEPTOR_H

#include "EventLoop.h"
#include "Connection.h"
#include "mem.h"

#include <memory>

#include <string>
extern std::string ServerTlsCertPath;
extern std::string ServerTlsKeyPath;

extern int PEEK_TIMEOUT;

class TlsAcceptor: public JobObject{
public:
    TlsAcceptor(int clientFd, const struct sockaddr_storage *remote_address);
    ~TlsAcceptor();

    // Memory allocation
    MEMPOOL_DECLARE(TlsAcceptor);

    void init();
    // JobObject implementation
    virtual const char *myname() const {return "Tunneler";}
    virtual void start() final;
    virtual bool done() final;
    virtual void shutdown() final;

    void tlsAccept(const Connection *c, short event);
    void tlsAcceptDone();

public:
    Connection client;
    IoCallJobT<TlsAcceptor> tlsAcceptCall;
};
#endif

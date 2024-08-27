#ifndef __CONNECTIONOPENER_H
#define __CONNECTIONOPENER_H

#include "Connection.h"
#include "DnsResolver.h"
#include "EventLoop.h"
#include <memory>
#include <vector>

struct sockaddr_storage;
class ConnectionOpenerUser:public JobObject {
public:
    virtual void serverConnected(Connection &conn) = 0;
};

class TlsClientSettings;
class ConnectionOpener: public JobObject {
public:
    ConnectionOpener(std::string &aServer, int aPort, ConnectionOpenerUser *aUser);
    ~ConnectionOpener();

    //JobObject implementation
    virtual const char *myname() const {return "ConnectionOpener";}
    virtual void start() final;
    virtual bool done() final {return false;} // Never finishes, only the caller/Tunneler is destroying ConnectionOpener object
    virtual void shutdown() final {}

    void connectionTry();
    void connectingResult(const Connection *c, short event);
    void tlsConnect(const Connection *c, short event);
    void noteAddresses(const std::string &servername, const std::vector<struct sockaddr_storage> *addresses, bool finalAnswer);
    void printOutStats();
public:
    Connection conn;
    std::string server;
    int port = 0;
    bool tlsEnabled = true;
    ConnectionOpenerUser *user = nullptr;
    uint64_t sessId = 0;
    std::shared_ptr<TlsClientSettings> tlsSettings;
    std::vector<struct sockaddr_storage> *addresses = nullptr;
    unsigned currentAddressesPos = 0;
    bool finalResolverAnswer = false;
    IoCallJobT<ConnectionOpener> clientConnectDone;
    IoCallJobT<ConnectionOpener> clientTlsConnect;
    AsyncCall *dnsResolverCall = nullptr;
    struct {
        uint64_t resolveTime = 0;
        uint64_t connectTime = 0;
        uint64_t lastConnectTime = 0;
        uint64_t tlsConnectTime = 0;
        struct timespec start = {0, 0};
        struct timespec connectStart = {0, 0};
        struct timespec connectStart1st = {0, 0};
        struct timespec resolveStart = {0, 0};
        struct timespec tlsConnectStart = {0, 0};
    } stats;
public:
    static bool NO_IPV6;
};


#endif

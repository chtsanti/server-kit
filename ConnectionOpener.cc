#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cassert>

#include "EventLoop.h"
#include "Connection.h"
#include "ConnectionOpener.h"
//#include "../tlsclient/tlsclient.h"
#include "utils.h"
#include "Bio.h"

std::vector<struct sockaddr_storage> TcpOutgoingAddresses;

bool ConnectionOpener::NO_IPV6 = false;

bool IsIpAddress(const char* address)
{
    sockaddr_in addr4;
    if (inet_pton(AF_INET, address, (void*)(&addr4)) == 1)
        return true;
    sockaddr_in6 addr6;
    if (inet_pton(AF_INET6, address, (void*)(&addr6)) == 1)
        return true;
    return false;
}

ConnectionOpener::ConnectionOpener(std::string &aServer, int aPort, ConnectionOpenerUser *aUser):
        server(aServer),
        port(aPort),
        user(aUser),
//        sessId(aTunnel && aTunnel->sessLog.get() ? aTunnel->sessLog->id : 0),
        clientConnectDone(&conn, this, &ConnectionOpener::connectingResult),
        clientTlsConnect(&conn, this, &ConnectionOpener::tlsConnect)
{
}

ConnectionOpener::~ConnectionOpener()
{
    DEBUG(5, "ConnectionOpener " << this << " destructing");
    if (dnsResolverCall)
        dnsResolverCall->cancel("ConnectionOpener gone");
    if (addresses)
        delete addresses;
    printOutStats();
}

MEMPOOL_IMPLEMENT_TMPL(CallNoteDnsResolved, ConnectionOpener)

void ConnectionOpener::start()
{
    conn.updateContext("ConnectionOpener::conn");
    if (!addresses) {
        clock_gettime (CLOCK_REALTIME, &stats.start);
        stats.resolveStart = stats.start;
        dnsResolverCall = new CallNoteDnsResolved<ConnectionOpener>(this, server);
        DnsResolver::ResolveName(server, dnsResolverCall);
    } else {
        connectionTry();
    }
}

void ConnectionOpener::noteAddresses(const std::string &servername, const std::vector<struct sockaddr_storage> *newAddresses, bool finalAnswer)
{
    if (newAddresses && newAddresses->size() != 0) {
        if (!addresses)
            addresses = new std::vector<struct sockaddr_storage>;
        addresses->insert(addresses->end(), newAddresses->begin(), newAddresses->end());
    }
    if (finalAnswer) {
        struct timespec resolveStop;
        clock_gettime (CLOCK_REALTIME, &resolveStop);
        stats.resolveTime = CLOCK_TIME_DIFF(resolveStop, stats.resolveStart);
        finalResolverAnswer = true;
        dnsResolverCall = nullptr;
    }
    connectionTry(); /*start connecting*/
}

void ConnectionOpener::connectionTry()
{
    if (user == nullptr) {
        DEBUG(4, "ConnectionOpener " << this << ", Caller gone/served, nothing to do");
        return;
    }

    if (conn.valid()) {
        DEBUG(5, "connection try on the go");
        assert(conn.flags.write_pending);
        return;
    }

    clock_gettime (CLOCK_REALTIME, &stats.connectStart);
    if (currentAddressesPos == 0)
        stats.connectStart1st = stats.connectStart;

    if (!addresses || addresses->size() == 0) {
        DEBUG(3, "Error opening connection to the remote server: Not valid addresses found");
        connectingResult(&conn, 0); // step done at one step
        return;
    }

    if (NO_IPV6) {
        // move forward untill an ipv4 address is found.
        while (currentAddressesPos < addresses->size() && addresses->at(currentAddressesPos).ss_family != AF_INET) currentAddressesPos++;
    }

    if (currentAddressesPos >= addresses->size()) {
        if (!finalResolverAnswer)
            return; /*Wait for more addresses*/
        DEBUG(3, "Addresses exhausted without connecting");
        connectingResult(&conn, 0); // step done at one step
        return;
    }

    struct sockaddr_storage &addr = addresses->at(currentAddressesPos);
    assert(addr.ss_family == AF_INET6 || addr.ss_family == AF_INET);
    DEBUG(5, "ConnectionOpener " << this << ", Going to connect to :" << print_sockaddr_storage(&addr))
    if (addr.ss_family == AF_INET6)
        ((struct sockaddr_in6 *) (&addr))->sin6_port = htons(port);
    else
        ((struct sockaddr_in *) (&addr))->sin_port = htons(port);

    errno = 0;
    int sock = socket(addr.ss_family, SOCK_STREAM, 0);
    if (sock == -1) {
        DEBUG(2, "Error opening socket: " << print_errno(errno));
        connectingResult(&conn, 0); // step done at one step
        return;
    }

    if (!TcpOutgoingAddresses.empty()) {
        uint64_t indx = (sessId >= TcpOutgoingAddresses.size()) ? sessId % TcpOutgoingAddresses.size() : sessId;
        struct sockaddr_storage localAddress;
        assert(indx < TcpOutgoingAddresses.size());
        memcpy(&localAddress, &TcpOutgoingAddresses[indx], sizeof(struct sockaddr_storage));
        int ret = bind(sock, (struct sockaddr *)&localAddress, sizeof(localAddress));
        if (ret != 0) {
            DEBUG(0, "Error binding local address");
        }
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    int ret;
    do {
        ret = connect(sock, (struct sockaddr *) &addr, addrlen);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0 && errno != EINPROGRESS) {
        DEBUG(3, "Failed to connect to remote host " << print_sockaddr_storage(&addr) << "  errno:" << std::dec << errno << "  / " << print_errno(errno) );
        connectingResult(&conn, 0); // step done at one step
        return;
    }
    conn.assign(sock, &addr);
    if (ret < 0 /*&& errno == EINPROGRESS*/) {
        conn.needsWrite(&clientConnectDone, CONNECT_TIMEOUT);
        DEBUG(5, "ConnectionOpener " << this <<" waits connecting to server");
    } else
        connectingResult(&conn, 0); // step done at one step
}

void ConnectionOpener::connectingResult(const Connection *c, short event)
{
    struct timespec connectStop;
    clock_gettime (CLOCK_REALTIME, &connectStop);
    stats.lastConnectTime = CLOCK_TIME_DIFF(connectStop, stats.connectStart);
    stats.connectTime = CLOCK_TIME_DIFF(connectStop, stats.connectStart1st);

    if (event & EV_TIMEOUT) {
        conn.close("ConnectionOpener::connectingResult timeout");
    }
    if (conn.valid()) {
        int errcode = 0;
        socklen_t len = sizeof(errcode);
        if (getsockopt(conn.fd, SOL_SOCKET, SO_ERROR, &errcode, &len) != 0) {
            errcode = errno;
        }
        if (errcode != 0) {
            DEBUG(3, "ConnectionOpener " << this << ", Connecting failed, result = " << print_errno(errcode));
            conn.close("ConnectionOpener::connectingResult errorcode");
        }
    }

    if (!conn.valid()) {
        DEBUG(3, "ConnectionOpener " << this << ", Connection try " << (currentAddressesPos + 1) << " failed");
        currentAddressesPos++; // Try the next available path
        if (addresses && currentAddressesPos < addresses->size()) {
            connectionTry();
            return;
        }
    } else {
        DEBUG(5, "ConnectionOpener " << this << ", Connection try " << (currentAddressesPos + 1) << " connected to " << conn);
    }

    if (conn.valid() && tlsEnabled) {
        tlsConnect(&conn, 0);
        return;
    }

    //callback:
    user->serverConnected(conn);
    conn.forget(); // Do not neeeded tunnel called steal.
    return;
}

static int openssl_verify_cert_cb (int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0) {
        DEBUG(2, "Peer cert verification failed: " <<  X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        return 1;
    }
    return 1;
}

class CallNoteConnection: public CallJob<ConnectionOpenerUser> {
public:
    CallNoteConnection(ConnectionOpenerUser *u, Connection &_conn) : CallJob<ConnectionOpenerUser>(u) {
        conn.steal(_conn);
    }
    virtual void call() {
        //callback
        obj->serverConnected(conn);
    }

    Connection conn;
};

void xxx_ssl_configure_SSL_CTX(SSL_CTX *ctx, const TlsClientSettings &settings);
void xxx_ssl_configure_SSL(SSL *ssl, const TlsClientSettings &settings);
void ConnectionOpener::tlsConnect(const Connection *c, short event)
{
    assert(c == &conn);

    if (event & EV_TIMEOUT) {
        conn.close("ConnectionOpener::tlsConnect timeout");
        connectingResult(&conn, 0);
        return;
    }

    if (!conn.ssl) {
        clock_gettime (CLOCK_REALTIME, &stats.tlsConnectStart);
        // initialize SSL;
        const SSL_METHOD *method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, openssl_verify_cert_cb);
        if (tlsSettings.get())
            xxx_ssl_configure_SSL_CTX(ctx, *tlsSettings);
        conn.ssl = SSL_new(ctx);
        SSL_CTX_free(ctx);
        ctx = nullptr;
#if 1
        BIO *bio = TunnelBio::Create(conn.fd);
        SSL_set_bio(conn.ssl, bio, bio);
#else
        SSL_set_fd(conn.ssl, conn.fd);
#endif
        //SSL_CTX_set_next_proto_select_cb();
        SSL_set_connect_state(conn.ssl);
        if (tlsSettings.get()) {
            xxx_ssl_configure_SSL(conn.ssl, *tlsSettings);
        } else if (!IsIpAddress(server.c_str())) {
            //No configured settings, just set server name
            SSL_set_tlsext_host_name(conn.ssl, server.c_str());
        }
    }

    int ret = Connection::TLS_Connect(conn, &clientTlsConnect);
    if (!ret)
        return; // retry.
    if (ret < 0)
        conn.close("ConnectionOpener::tlsConnect TLS_Connect error");

    struct timespec connectStop;
    clock_gettime (CLOCK_REALTIME, &connectStop);
    stats.tlsConnectTime = CLOCK_TIME_DIFF(connectStop, stats.tlsConnectStart);
    DEBUG(5, "ConnectionOpener " << this << ", " << conn << " TLS negotiation to server is finished: " << ret);
    AsyncCall *call = new CallNoteConnection(user, conn);
    AsyncCall::Schedule(call);
}

void ConnectionOpener::printOutStats()
{
    DEBUG(5,
        "ConnectionOpener " << this
        << " resolveTime:" << stats.resolveTime
        << " connectTime:" << stats.connectTime
        << " lastConnectTime:" << stats.lastConnectTime
        << " tlsConnectTime:" << stats.tlsConnectTime
        );
}

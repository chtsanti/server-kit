#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "Connection.h"
#include "utils.h"
#include "Config.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <climits>

int READ_TIMEOUT = 60;
int WRITE_TIMEOUT = 60;
int CONNECT_TIMEOUT = 30;
int KEEPALIVE_TIMEOUT = 60*2;
std::atomic<uint64_t> IOBUFFER_allocs(0);
std::atomic<uint64_t> IOBUFFER_frees(0);

void Connection::assign(int anFd, const struct sockaddr_storage *remote, const struct sockaddr_storage *local)
{
    assert(fd < 0);
    fd = anFd;
    if (local) {
        memcpy(&addr_local, local, sizeof(struct sockaddr_storage));
    } else {
        socklen_t claddrlen = sizeof(struct sockaddr_storage);
        if (getsockname(fd, (struct sockaddr *)&addr_local, &claddrlen) < 0)
            memset(&addr_local, 0, sizeof(addr_local));
    }
    memcpy(&addr_remote, remote, sizeof(struct sockaddr_storage));
}

class CallFakeIoCall: public AsyncCall {
public:
    CallFakeIoCall(Call *aCall, Connection *c, short ev) : AsyncCall("CallIoCall"), ioc(aCall), conn(c), events(ev) {}
    virtual void call() {
        assert(conn);
        assert(conn->tlsFakeIo == this);
        DEBUG(7, "FakeIoCall " << this << " " << ioc->name);
        conn->tlsFakeIo = nullptr;
        ioc->updateFlags(conn->fd, events);
        ioc->call();
    }
    virtual void finish() {};
    Call *ioc;
    Connection *conn;
    short events;
};

void Connection::needsRead(Call *callback, int timeout)
{
    // Should we assert on read_pending?
    if (flags.read_pending == true) {
        DEBUG(3, *this << " a read already scheduled");
        return;
    }
    // Should we assert on closed socket?
    if (fd < 0) {
        DEBUG(2, *this << " connection is closed, ignore");
        return;
    }
    // BIO_pending check is disabled because currently the TunnelBio
    // Does not support read-ahead operation.
    int ret1;
    if (ssl && ((ret1 = SSL_pending(ssl)) /*||extern int KEEPALIVE_TIMEOUT; (ret2 = BIO_pending(SSL_get_rbio(ssl)))*/)) {
        int bio_pending = BIO_pending(SSL_get_rbio(ssl));
        DEBUG(4, *this << " TLS pending bytes, schedule a fake read to get it SSLpending:" << ret1 << " bio pending:" << bio_pending);
        flags.read_pending = true;
        tlsFakeIo = new CallFakeIoCall(callback, this, EV_READ);
        AsyncCall::Schedule(tlsFakeIo);
        return;
    }
    DEBUG(5, *this << " request a read");
    initLibEventIO(callback, nullptr);
    assert(read_event);
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    event_add(read_event, (timeout == 0 ? NULL : &tv));
    flags.read_pending = true;
    read_timeout = timeout;
}

bool Connection::clearRead()
{
    if (!flags.read_pending) {
        FAIL("Connection " << *this << "clearRead: read event is not registered");
        return false;
    }
    if (tlsFakeIo) {
        FAIL("Connection " << *this << "clearRead: read event is not registered");
        return false;
    }
    assert(read_event);
    int ret = event_del(read_event);
    if (ret < 0) {
        FAIL("Connection " << *this << " Error clearing read event");
        return false;
    }
    flags.read_pending = false;
    read_timeout = 0;
    return true;
}

bool Connection::clearWrite()
{
    if (!flags.write_pending) {
        FAIL("Connection " << *this << "clearWrite: write event is not registered");
        return false;
    }
    assert(write_event);
    int ret = event_del(write_event);
    if (ret < 0) {
        FAIL("Connection " << *this << " Error clearing write event");
        return false;
    }
    flags.write_pending = false;
    write_timeout = 0;
    return true;
}

void Connection::needsWrite(Call *callback, int timeout)
{
    // Should we assert on write_pending?
    if (flags.write_pending == true) {
        DEBUG(3, *this << " a read already scheduled");
        return;
    }
    // Should we assert on closed socket?
    if (fd < 0) {
        DEBUG(2, *this << " connection is closed, ignore");
        return;
    }
    DEBUG(5, *this << " request a write");
    initLibEventIO(nullptr, callback);
    assert(write_event);
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    event_add(write_event, (timeout == 0 ? NULL : &tv));
    flags.write_pending = true;
    write_timeout = timeout;
}

bool Connection::doRead(IoBuffer &readBuffer)
{
    ssize_t result;
    size_t capacity = readBuffer.capacity();
    size_t readbuf_existing_data = readBuffer.size();
    IoBufferExpand(&readBuffer, capacity);
    size_t rbuf_space = capacity - readbuf_existing_data;
    void *rbuf = readBuffer.data() + readbuf_existing_data;
    assert(rbuf_space);
    assert(fd >=0);
    if (ssl) {
        while(ERR_get_error());
        errno = 0;
        result = SSL_read(ssl, rbuf, rbuf_space);
        int lastErrno = errno;
        if (result > 0) {
            DEBUG(5, *this << " TLS read " << result << " bytes");
        } else {
            unsigned long err = 0;
            int sslError = SSL_get_error(ssl, result);
            switch (sslError) {
            case SSL_ERROR_ZERO_RETURN:
                DEBUG(5, *this << " SSL_read failed because connection is closed");
                return false;
            case SSL_ERROR_WANT_READ:
                DEBUG(4, *this << " SSL_read needs retry read");
                result = 0; // will return true
                break;
            case SSL_ERROR_WANT_WRITE:
                DEBUG(3, *this << " SSL_read wants write to read? error will abort");
                return false;
            case SSL_ERROR_SYSCALL:
                DEBUG(3, *this << " SSL_read syscall IO error: " << (lastErrno ? print_errno(lastErrno) : " 0/unexpected close"));
                flags.fatal_error = true;
                return false;
            case SSL_ERROR_SSL: {
                char buf[256];
                //TODO: retrieve the error
                err = ERR_get_error();
                ERR_error_string_n(err, buf, sizeof(buf));
                DEBUG(3, *this << " SSL_read TLS error: " << buf);
                flags.fatal_error = true;
                return false;
            }
            default:
                DEBUG(3, *this << " SSL_read error : " << sslError);
                flags.fatal_error = true;
                return false;
            }
        }
    } else {
        errno = 0;
        do {
            result = recv(fd, rbuf, rbuf_space, 0);
        } while (result == -1 && errno == EINTR);
        if (result == 0) {
            // Is eof, Connection closed?
            return false;
        }
        if (result < 0) {
            if (errno == EAGAIN) {
                return true;
            }
            // An error?
            DEBUG(3, *this << " recv error: " << print_errno(errno));
            flags.fatal_error = true;
            return false;
        }
        DEBUG(5, *this << " read " << result << " bytes");
    }

    assert(result >= 0);
    IoBufferCrop(readBuffer, readbuf_existing_data + result);
    return true;
}

bool Connection::doWrite(IoBuffer &outBuffer)
{
    const void *out = outBuffer.data();
    size_t len = outBuffer.size();
    ssize_t result;
    assert(fd >=0);
    if (ssl) {
        while(ERR_get_error());
        errno = 0;
        result = SSL_write(ssl, out, len);
        int lastErrno = errno;
        if (result == 0) {
            DEBUG(3, *this << " TLS write failure? Return: " << result);
            return false;
        }
        if (result < 0) {
            unsigned long err = 0;
            int sslError = SSL_get_error(ssl, result);
            switch (sslError) {
            case SSL_ERROR_ZERO_RETURN:
                DEBUG(5, *this << " SSL_write failed because connection is closed");
                break;
            case SSL_ERROR_WANT_READ:
                DEBUG(3, *this << " SSL_write wants to read before write? error will abort");
                break;
            case SSL_ERROR_WANT_WRITE:
                DEBUG(4, *this << " SSL_write needs to retry write");
                return true;
            case SSL_ERROR_SYSCALL:
                DEBUG(3, *this << " SSL_write syscall IO error: " << (lastErrno ? print_errno(lastErrno) : " 0/unexpected close"));
                flags.fatal_error = true;
                break;
            case SSL_ERROR_SSL: {
                char buf[256];
                //TODO: retrieve the error
                err = ERR_get_error();
                ERR_error_string_n(err, buf, sizeof(buf));
                DEBUG(3, *this << " SSL_write TLS error: " << buf);
            }
                flags.fatal_error = true;
                break;

            default:
                flags.fatal_error = true;
                DEBUG(3, *this << " Other error: " << sslError);
            }
            return false;
        }
        DEBUG(5, *this << " TLS write " << result << " bytes");
    } else {
        errno = 0;
        do {
            result = send(fd, out, len, 0);
        } while (result == -1 && errno == EINTR);
        if (result < 0) {
            if (errno == EAGAIN) {
                return true; /*ignore error*/
            }
            // An error?
            DEBUG(3, *this << " send error: " << print_errno(errno));
            flags.fatal_error = true;
            return false;
        }
        DEBUG(5, *this << " write " << result << " bytes");
    }
    IoBufferConsume(outBuffer, result);
    return true;
}

bool Connection::initLibEventIO(Call *r, Call *w)
{
    assert(fd >=0);
    if (r) {
        if (!read_event)
            read_event = event_new(EventBase, fd, EV_READ, Call::DoCall, r);
        else
            event_assign(read_event, EventBase, fd, EV_READ, Call::DoCall, r);
        assert(read_event);
    }
    if (w) {
        if (!write_event)
            write_event = event_new(EventBase, fd, EV_WRITE, Call::DoCall, w);
        else
            event_assign(write_event, EventBase, fd, EV_WRITE, Call::DoCall, w);
        assert(write_event);
    }
    return true;
}

void Connection::close(const char *reason)
{
    closeReason = reason;
    DEBUG(5, "Connection " << *this << " is " << (fd > 0 ? "closing" : "already closed") << (closeReason ? " because of " : "") << (closeReason ? closeReason : ""));
    if (flags.read_pending) {
        // remove read event
        int ret = event_del(read_event);
        if (ret < 0) {
            FAIL("Connection " << *this << " Error removing read event");
        } else
            flags.read_pending = false;
    }
    if (flags.write_pending) {
        // remove write event
        int ret = event_del(write_event);
        if (ret < 0) {
            FAIL("Connection " << *this << " Error removing write event");
        } else
            flags.write_pending = false;
    }
    if (read_event) {
        event_free(read_event);
        read_event = nullptr;
    }
    if (write_event) {
        event_free(write_event);
        write_event = nullptr;
    }
    read_timeout = 0;
    write_timeout = 0;
    if (tlsFakeIo) {
        tlsFakeIo->cancel("Connection is closed");
        tlsFakeIo = nullptr;
    }

    if (!flags.fatal_error && !flags.close_pending && ssl) {
        if (initiate_graceful_tls_shutdown())
            return;
    }

    if (fd > 0) {
        ::close(fd);
        fd = -1;
    }
    if (ssl) {
        SSL_free(ssl);
        ssl = nullptr;
    }
}

Connection::~Connection()
{
    close();
    DEBUG(5, "Connection " << this << " is destructing");
}

inline int sockaddr_storage_port(const struct sockaddr_storage *addr)
{
    if (addr->ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    else if (addr->ss_family == AF_INET6)
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    else
        return -1;
}

std::ostream &operator << (std::ostream &os, const Connection &conn)
{
    if (conn.fd <= 0)
        os << "[" << std::dec << conn.fd << " p: " << (void *)&conn << "]";
    else {
        os << "[" << std::dec << conn.fd << " remote:" << print_sockaddr_storage(&conn.addr_remote) << ":" << sockaddr_storage_port(&conn.addr_remote)
           << " local:" << print_sockaddr_storage(&conn.addr_local) << ":" << sockaddr_storage_port(&conn.addr_local);
        os << " IO-Pending=";
        if (conn.flags.read_pending)
            os <<"R";
        if (conn.flags.write_pending)
            os << "W";
        os << " p:" << (void *)&conn;
        if (conn.ssl)
            os << " ssl:" << conn.ssl;
        os << "]";
    }
    return os;
}

// To be used for SSL_accept, SSL_connect and SSL_Shutdown calls.
// TODO: probably use it to wrap  SSL_read/SSL_write calls
template <typename SSL_FUNC> int openssl_io_call(const char *operation, Connection &conn, Call *onIo, int timeout, SSL_FUNC ssl_io_func)
{
    if (!conn.ssl)
        return INT_MIN;
    while(ERR_get_error());
    errno = 0;
    int result = ssl_io_func(conn.ssl);
    int lastErrno = errno;
    if (result > 0) {
        DEBUG(5, conn << " " << operation << " completed");
        return 1;
    }
    unsigned long err = 0;
    int sslError = SSL_get_error(conn.ssl, result);
    switch (sslError) {
    case SSL_ERROR_WANT_READ:
        DEBUG(4, conn << " " << operation << " needs to read more");
        conn.needsRead(onIo, timeout);
        return 0;
    case SSL_ERROR_WANT_WRITE:
        DEBUG(4, conn << " " << operation << " needs to write more");
        conn.needsRead(onIo, timeout);
        return 0;
    case SSL_ERROR_ZERO_RETURN:
        DEBUG(5, conn << " " << operation <<  " Connection is closed by remote end");
        return -1;
    case SSL_ERROR_SYSCALL:
        DEBUG(3, conn << " " << operation << " Connection IO error: " << (lastErrno ? print_errno(lastErrno) : " 0/unexpected close"));
        conn.flags.fatal_error = true;
        return -1;
    case SSL_ERROR_SSL: {
        char buf[256];
        err = ERR_get_error();
        ERR_error_string_n(err, buf, sizeof(buf));
        DEBUG(3, conn << " " << operation << " TLS error: " << buf);
        conn.flags.fatal_error = true;
        return -1;
    }
    default:
        DEBUG(3, conn << " " << operation << " unknown error : " << sslError);
        conn.flags.fatal_error = true;
        return -1;
    }
    return -1;
}

int Connection::TLS_Accept(Connection &conn, Call *onIo)
{
    return openssl_io_call("SSL_accept", conn, onIo, READ_TIMEOUT, SSL_accept);
}

int Connection::TLS_Connect(Connection &conn, Call *onIo)
{
    return openssl_io_call("SSL_connect", conn, onIo, CONNECT_TIMEOUT, SSL_connect);
}

#define CLOSE_TIMEOUT 10
class TlsConnCloser: public JobObject {
public:
    TlsConnCloser(Connection &c):
        closerCall(&conn, this, &TlsConnCloser::tlsClose) {
        conn.steal(c);
        conn.updateContext(conn.closeReason);
        conn.flags.close_pending = true;
    }
    virtual const char *myname() const {return "TlsConnCloser";}
    virtual bool done() final {return conn.closed();}
    virtual void shutdown() final {}
    virtual void start() final {
        conn.needsWrite(&closerCall);
    }

    void tlsClose(const Connection *c, short event) {
        DEBUG(5, "TlsConnCloser " << this << " for " << conn << " shutdown step");
        if (event & EV_TIMEOUT) {
            conn.flags.fatal_error = true;
            conn.close("TlsConnCloser::tlsClose timeout");
            return;
        }
        bool done = true;
        if ((event & EV_READ) && shutdownSent) {
            (void)openssl_io_call("SSL_Linger", conn, &closerCall, CLOSE_TIMEOUT, [](SSL *ssl){ char buf[256]; return SSL_read(ssl, (void *)buf, sizeof(buf));});
            // No need to linger more bytes, one read is enough to give a chance
            // for a graceful bidirectional shutdown.
            done = true;
        } else {
            int ret = openssl_io_call("SSL_shutdown", conn, &closerCall, CLOSE_TIMEOUT,
                                      [this](SSL *ssl) {
                                          int ret = SSL_shutdown(ssl);
                                          if (ret == 0) {
                                              this->shutdownSent = true;
                                              this->conn.needsRead(&this->closerCall, CLOSE_TIMEOUT);
                                              return 1;
                                          }
                                          return ret;
                                      }
                );
            if (shutdownSent)
                done = false;
            else
                done = (ret != 0);
        }
        if (!done)
            return;
        // Error or successful, just close
        conn.close("TlsConnCloser::tlsClose");
    }

    Connection conn;
    IoCallJobT<TlsConnCloser> closerCall;
    bool shutdownSent = false;;
};

bool Connection::initiate_graceful_tls_shutdown()
{
    if (!TLS_NEGOTIATE_SHUTDOWN) {
        DEBUG(5, *this << " Try to send TLS_shutdown once and hard close connection");
        SSL_shutdown(ssl);
        return false;
    } else {
        DEBUG(5, *this << " graceful tls shutdown");
        auto closer = new TlsConnCloser(*this);
        closer->start();
        return true;
    }
}

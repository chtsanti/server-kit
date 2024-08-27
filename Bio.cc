#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <cassert>
#include <cstring>
#include <unistd.h>

#include "EventLoop.h"
#include "Bio.h"
#include "utils.h"

static int tunnel_bio_write(BIO *h, const char *buf, int num);
static int tunnel_bio_read(BIO *h, char *buf, int size);
static long tunnel_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int tunnel_bio_create(BIO *h);
static int tunnel_bio_destroy(BIO *data);
static BIO_METHOD *TunnelMethod = nullptr;

BIO *TunnelBio::Create(const int fd)
{
    if (!TunnelMethod) {
        TunnelMethod = BIO_meth_new(BIO_TYPE_SOCKET, "tunneler");
        BIO_meth_set_write(TunnelMethod, tunnel_bio_write);
        BIO_meth_set_read(TunnelMethod, tunnel_bio_read);
        BIO_meth_set_puts(TunnelMethod, nullptr);
        BIO_meth_set_gets(TunnelMethod, nullptr);
        BIO_meth_set_ctrl(TunnelMethod, tunnel_bio_ctrl);
        BIO_meth_set_create(TunnelMethod, tunnel_bio_create);
        BIO_meth_set_destroy(TunnelMethod, tunnel_bio_destroy);
    }
    if (BIO *bio = BIO_new(TunnelMethod)) {
        BIO_int_ctrl(bio, BIO_C_SET_FD, fd, 0);
        return bio;
    }
    return nullptr;
}

TunnelBio::TunnelBio(const int anFd): fd_(anFd)
{}

TunnelBio::~TunnelBio()
{
    // just forget fd, will be closed by Tunneler
}

int TunnelBio::write(const char *buf, int size, BIO *table)
{
    errno = 0;
    int result;
    assert(size > 0 && "TunnelBio::write");
    do {
        result = ::write(fd_, buf, size);
    } while(result == -1 && errno == EINTR);
    int xerrno = errno;
    BIO_clear_retry_flags(table);
    if (result < 0) {
        if (xerrno == EAGAIN) {
            DEBUG(5, " TunnelBio fd: " << fd_ << " no bytes write, needs retry");
            BIO_set_retry_write(table);
        } else {
            DEBUG(3, " TunnelBio fd: " << fd_ << " write error: " << print_errno(xerrno));
        }
    }
    return result;
}

int TunnelBio::read(char *buf, int size, BIO *table)
{
    DEBUG(7, "TunnelBio fd: " << fd_ << " request to get " << size << " bytes");
    if (rbuf.length()) {
        int getBytes = (int)rbuf.length() > size ? size : rbuf.length();
        memcpy(buf, rbuf.data(), getBytes);
        rbuf.erase(0, getBytes);
        return getBytes;
    }
    errno = 0;
    int result;
    assert(size > 0 && "TunnelBio::read");
    do {
        result = ::read(fd_, buf, size);
    } while (result == -1 && errno == EINTR);
    int xerrno = errno;
    BIO_clear_retry_flags(table);
    if (result < 0) {
        if (xerrno == EAGAIN) {
            DEBUG(5, " TunnelBio fd: " << fd_ << " no bytes read, needs retry");
            BIO_set_retry_read(table);
        } else {
            DEBUG(3, " TunnelBio fd: " << fd_ << " read error: " << print_errno(xerrno));
        }
    }
    return result;
}

void TunnelBio::flush(BIO *table)
{
}

void TunnelBio::addToReadBuffer(const char *buf, size_t len)
{
    rbuf.append(buf, len);
}

static int tunnel_bio_create(BIO *bi)
{
    BIO_set_data(bi, nullptr);
    return 1;
}

static int tunnel_bio_destroy(BIO *table)
{
    delete static_cast<TunnelBio*>(BIO_get_data(table));
    BIO_set_data(table, nullptr);
    return 1;
}

static int tunnel_bio_write(BIO *table, const char *buf, int size)
{
    TunnelBio *bio = static_cast<TunnelBio*>(BIO_get_data(table));
    assert(bio);
    return bio->write(buf, size, table);
}

static int tunnel_bio_read(BIO *table, char *buf, int size)
{
    TunnelBio *bio = static_cast<TunnelBio*>(BIO_get_data(table));
    assert(bio);
    return bio->read(buf, size, table);
}

#if 0
static int tunnel_bio_puts(BIO *table, const char *str)
{
    assert(str);
    return tunnel_bio_write(table, str, strlen(str));
}
#endif

static long tunnel_bio_ctrl(BIO *table, int cmd, long arg1, void *arg2)
{
    switch (cmd) {
    case BIO_C_SET_FD: {
        assert(arg1);
        const int fd = static_cast<int>(arg1);
        TunnelBio *bio;
        bio = new TunnelBio(fd);
        assert(!BIO_get_data(table));
        BIO_set_data(table, bio);
        BIO_set_init(table, 1);
        return 0;
    }

    case BIO_C_GET_FD:
        if (BIO_get_init(table)) {
            TunnelBio *bio = static_cast<TunnelBio*>(BIO_get_data(table));
            assert(bio);
            if (arg2)
                *static_cast<int*>(arg2) = bio->fd();
            return bio->fd();
        }
        return -1;

    case BIO_CTRL_DUP:
        return -1;

    case BIO_CTRL_FLUSH:
        if (BIO_get_init(table)) {
            TunnelBio *bio = static_cast<TunnelBio*>(BIO_get_data(table));
            assert(bio);
            bio->flush(table);
            return 1;
        }
        return 0;

    case BIO_CTRL_PENDING: {
        TunnelBio *bio = static_cast<TunnelBio*>(BIO_get_data(table));
        long ret = (long)bio->rBufData().length();
        DEBUG(5, "Bio pending bytes: " << ret);
        return ret;
    }
    default:
        return 0;

    }

    return 0;
}

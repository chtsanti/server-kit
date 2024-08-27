#ifndef __CONNECTION_H
#define __CONNECTION_H

#include "EventLoop.h"

#include <openssl/ssl.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <atomic>

#include "mem.h"

extern int READ_TIMEOUT;
extern int WRITE_TIMEOUT;
extern int CONNECT_TIMEOUT;
extern int KEEPALIVE_TIMEOUT;

#define  IOBUFFER_MAX_SIZE 32768
// TODO: implement a new class for IoBuffer
#if 0
typedef std::vector<unsigned char> IoBuffer;
// Hack to add new items to a vector<uchar> object without initialize
// vector elements.
// It casts the std::vector<unsigned char> to std::vector<uninitializedUChar>
// to use empty constructor as constructor of 'char' vector elements
// The Compiler optimization (-O2/-O3) will remove the for-loop
// which will call empty constructor for each new vector item.
inline void IoBufferExpand(IoBuffer *buf, size_t new_size) {
    class uninitializedUChar {
    public:
        uninitializedUChar() {};
        uninitializedUChar(int i) : c(i) {};
        operator unsigned char () const { return c; }
    private:
        unsigned char c;
    };
    if (new_size <= buf->size())
        return; // do nothing
    buf->reserve(new_size);
    std::vector<uninitializedUChar> *uv = reinterpret_cast<std::vector<uninitializedUChar> *>(buf);
    uv->resize(new_size);
}
#else

// Hack to add new items to a vector<uchar> object without initialize
// vector elements.
// The IoBufferAllocator overwrites rebind member and
// construct method to nont initialize unsigned char elements.
// The Compiler optimization (-O2/-O3) will remove empty code.
#define IOBUFFER_ALLOCATE_SIZE IOBUFFER_MAX_SIZE
extern std::atomic<uint64_t> IOBUFFER_allocs;
extern std::atomic<uint64_t> IOBUFFER_frees;
template <typename T, typename A=std::allocator<T>>
class IoBufferAllocator : public A {
    typedef std::allocator_traits<A> a_t;
public:
    template <typename U> struct rebind {
        using other =
            IoBufferAllocator<U, typename a_t::template rebind_alloc<U> >;
    };

    using A::A;

    T* allocate (size_t n, const T *hint=0) {
        assert(n <= IOBUFFER_ALLOCATE_SIZE);
        T *mem = nullptr;
        if (hint == nullptr) {
            mem = (T *)ci_buffer_alloc(IOBUFFER_ALLOCATE_SIZE);
            IOBUFFER_allocs++;
        } else {
            size_t bufSize = ci_buffer_size(hint);
            assert(bufSize >= IOBUFFER_ALLOCATE_SIZE);
            mem = (T *)hint;
        }
        assert(mem);
        return mem;
    }
    void deallocate (T *p, size_t n) {
        assert(n <= IOBUFFER_ALLOCATE_SIZE);
        ci_buffer_free(p);
        IOBUFFER_frees++;
    }

    template <typename U>
    void construct(U* ptr) noexcept(std::is_nothrow_default_constructible<U>::value) {
        ::new(static_cast<void*>(ptr)) U;
    }
    template <typename U, typename...Args>
    void construct(U* ptr, Args&&... args) {
        a_t::construct(static_cast<A&>(*this), ptr, std::forward<Args>(args)...);
        // Should enabled to avoid slow buffers append operations
        // assert(!"should not used");
    }
};

typedef std::vector<unsigned char, IoBufferAllocator<unsigned char>> IoBuffer;

inline void IoBufferExpand(IoBuffer *buf, size_t new_size) {
    buf->resize(new_size);
}
#endif

inline void IoBufferConsume(IoBuffer &buf, size_t bytes) {
    size_t remains = buf.size() - bytes;
    if (remains)
        memmove(buf.data(), buf.data() + bytes, remains);
    buf.resize(remains);
}

inline size_t IoBufferSpace(const IoBuffer &buf) {
    return buf.capacity() - buf.size();
}

inline void IoBufferCrop(IoBuffer &buf, size_t new_size) {
    if (buf.size() <= new_size)
        return; // do nothing
    buf.resize(new_size);
}

inline size_t IoBufferMove(IoBuffer &dst, IoBuffer &src)
{
    const size_t copyBytes = std::min(IoBufferSpace(dst), src.size());
    const size_t currentLen = dst.size();
    IoBufferExpand(&dst, currentLen + copyBytes);
    memcpy(dst.data() + currentLen, src.data(), copyBytes);
    IoBufferConsume(src, copyBytes);
    return copyBytes;
}

inline size_t IoBufferAppend(IoBuffer &dst, const char *bytes, size_t length)
{
    const size_t copyBytes = std::min(IoBufferSpace(dst), length);
    const size_t currentLen = dst.size();
    IoBufferExpand(&dst, currentLen + copyBytes);
    memcpy(dst.data() + currentLen, bytes, copyBytes);
    return copyBytes;
}

class Connection {
public:
    Connection(int anFd, const struct sockaddr_storage *remote_address) {
        fd = -1;
        assign(anFd, remote_address);
    };
    Connection() {}
    ~Connection();
    bool initLibEventIO(Call *readCall, Call *writeCall);
    bool doRead(IoBuffer &readBuffer);
    bool doWrite(IoBuffer &outBuffer);
    void needsRead(Call *callback, int timeout = READ_TIMEOUT);
    void needsWrite(Call *callback, int timeout = WRITE_TIMEOUT);
    bool readPending() { return flags.read_pending; }
    bool writePending() { return flags.write_pending; }
    bool clearRead();
    bool clearWrite();
    bool valid() { return fd >= 0;}
    bool closed() { return fd < 0;}
    void close(const char *reason = "normal");

    void assign(int fd, const struct sockaddr_storage *remote_address, const struct sockaddr_storage *local_address = nullptr);
    void steal(Connection &other) {
        assign(other.fd, &other.addr_remote, &other.addr_local);
        ssl = other.ssl;
        other.forget();
    }

    void forget() {
        fd = -1;
        ssl = nullptr;
        close();
    }

    void updateContext(const char *ctx) {
        context = ctx;
    }
private:
    bool initiate_graceful_tls_shutdown();
public:
    static int TLS_Accept(Connection &conn, Call *onIo);
    static int TLS_Connect(Connection &conn, Call *onIo);

public:
    int fd = -1;
    SSL *ssl = nullptr;
    AsyncCall *tlsFakeIo = nullptr; // Check if we need to keep list of Calls
    struct event *read_event = nullptr;
    struct event *write_event = nullptr;
    struct {
        bool read_pending = 0;
        bool write_pending = 0;
        bool fatal_error = false;
        bool close_pending = false;
    } flags;
    int read_timeout =0;
    int write_timeout =0;
    struct sockaddr_storage addr_remote;
    struct sockaddr_storage addr_local;
    const char *context = "none";
    const char *closeReason = nullptr;
};

std::ostream &operator << (std::ostream &os, const Connection &conn);

#endif


#ifndef __BIO_H
#define __BIO_H

#include <string>
#include <openssl/bio.h>

class TunnelBio
{
public:
    TunnelBio(const int anFd);
     ~TunnelBio();
    int write(const char *buf, int size, BIO *table);
    int read(char *buf, int size, BIO *table);
    void flush(BIO *);
    int fd() const { return fd_; }
    const std::string &rBufData() {return rbuf;}
    void addToReadBuffer(const char *buf, size_t len);
public:
    std::string apln;
private:
    const int fd_;
    std::string rbuf;  ///< Used to buffer input data.

public:
    static BIO *Create(const int fd);

};

#endif // __BIO_H

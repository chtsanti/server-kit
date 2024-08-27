#ifndef __TLSUTILS_H
#define  __TLSUTILS_H

#include <string>
#include <memory>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

struct X509Deletor {
    void operator()(X509 *a) { X509_free(a); }
};

typedef std::unique_ptr<X509, X509Deletor> CERT_ptr;

struct PKEYDeletor {
    void operator()(EVP_PKEY *a) { EVP_PKEY_free(a); }
};
typedef std::unique_ptr<EVP_PKEY, PKEYDeletor> PKEY_ptr;

void tlsInit();
void tlsDown();

CERT_ptr readCertFromFile(const char *filename);
PKEY_ptr readPkeyFromFile(const char *filename);
CERT_ptr readCert(const char *, size_t);
PKEY_ptr readPkey(const char *, size_t);
bool writeCert(const CERT_ptr &cert, std::string &out);
bool writePKey(const PKEY_ptr &pkey, std::string &out);

bool printCertSubjectName(const CERT_ptr &cert, std::string &out);
void printCertSignature(const CERT_ptr &cert, std::string &out);
bool certExpiresAfterSeconds(const CERT_ptr &cert, int64_t &secs);

class TlsClientSettings {
public:
    bool parseCiphers(std::string &ciphers);
    bool parseVersion(std::string &version);
    bool parseOptions(std::string &opts);
public:
    std::string sni;
    std::string cipher_suites;
    std::string ciphers;
    std::string options;
    std::string max_version;
    std::vector<uint16_t> supported_versions;
    std::string tlsAppLayerProtoNeg;
    std::string signatureAlgorithsCert;
    bool encryptedClientHello = false;
    bool greased = false;
    bool status_request = false;
    bool signedCertsTimestamps = false;
    bool permuteExtensions = false;
};
void xxx_ssl_configure_SSL_CTX(SSL_CTX *ctx, const TlsClientSettings &settings);

#endif

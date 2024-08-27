#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <assert.h>

#include "EventLoop.h"
#include "Debug.h"
#include "openssl/TLSutils.h"
#include "openssl/openssl_options.cci"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define X509_getm_notAfter X509_get_notAfter
#define X509_getm_notBefore X509_get_notBefore
#define X509_set1_notAfter X509_set_notAfter
#define X509_set1_notBefore X509_set_notBefore
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static bool BIO_set_string(BIO &bio, std::string &out);
#endif
static BIO* BIO_new_string(std::string* out);

bool printCertSubjectName(const CERT_ptr &cert, std::string &out)
{
    if (!cert.get()) {
        out.append("-");
        return false;
    }
    BIO *output_bio = BIO_new(BIO_s_mem());
    X509_NAME *subject = X509_get_subject_name(cert.get());
    if (!subject) {
        out.append("-");
        return false;
    }
    // Print the subject into a BIO and then get a string
    X509_NAME_print_ex(output_bio, subject, 0, 0);
    char *outData;
    size_t outDataSize = BIO_get_mem_data(output_bio, &outData);
    out.append(outData, outDataSize);
    BIO_free(output_bio);
    return true;
}

void printCertSignature(const CERT_ptr &cert, std::string &out)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ASN1_BIT_STRING *sig = nullptr;
    X509_ALGOR *sig_alg = nullptr;
#else
   const ASN1_BIT_STRING *sig = nullptr;
   const X509_ALGOR *sig_alg = nullptr;
#endif
    X509_get0_signature(&sig, &sig_alg, cert.get());
    if (sig && sig->data) {
        const unsigned char *s = sig->data;
        for (int i = 0; i < sig->length; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", s[i]);
            out.append(hex);
        }
    }
}

CERT_ptr readCertFromFile(const char *filename)
{
    BIO *bio = BIO_new_file(filename, "r");
    X509 *cert = PEM_read_bio_X509(bio, nullptr, 0, 0);
    BIO_free(bio);
    return CERT_ptr(cert); // unique_ptr move constructor allow this
}

PKEY_ptr readPkeyFromFile(const char *filename)
{
    BIO *bio = BIO_new_file(filename, "r");
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, 0, 0);
    BIO_free(bio);
    return PKEY_ptr(key);  // unique_ptr move constructor allow this
}

CERT_ptr readCert(const char *str, size_t len)
{
    BIO *bio = BIO_new_mem_buf(str, len);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, 0, 0);
    BIO_free(bio);
    return CERT_ptr(cert); // unique_ptr move constructor allow this
}

PKEY_ptr readPkey(const char *str, size_t len)
{
    BIO *bio = BIO_new_mem_buf(str, len);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, 0, 0);
    BIO_free(bio);
    return PKEY_ptr(key);  // unique_ptr move constructor allow this
}

bool writeCert(const CERT_ptr &cert, std::string &out)
{
    if (!cert.get())
        return false;

    BIO *output_bio = BIO_new_string(&out);
    int ret = PEM_write_bio_X509(output_bio, cert.get());
    BIO_free(output_bio);
    return ret;
}

bool writePKey(const PKEY_ptr &pkey, std::string &out)
{
    if (!pkey.get())
        return false;

    BIO *output_bio = BIO_new_string(&out);
    int ret = PEM_write_bio_PrivateKey(output_bio, pkey.get(), NULL, NULL, 0, NULL, NULL);
    BIO_free(output_bio);
    return ret;
}

bool certExpiresAfterSeconds(const CERT_ptr &cert, int64_t &seconds)
{
    ASN1_TIME *aTime = X509_getm_notAfter(cert.get());

    int day, sec;
    if (!ASN1_TIME_diff(&day, &sec, NULL, aTime))
        return false;

    seconds = static_cast<int64_t>(day)*24*60*60 + static_cast<int64_t>(sec);
    return true;
}

int openssl_option(const char *opt)
{
    int i;
    for (i = 0; OPENSSL_OPTS[i].name != NULL; ++i) {
        if (0 == strcmp(opt, OPENSSL_OPTS[i].name)) {
            return OPENSSL_OPTS[i].value;
        }
    }
    return 0;
}

int TLS_parse_options(const char *str, long *options)
{
    std::cout << "OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION) << "\n";
    char *stroptions = strdup(str);
    char *sopt, *next = NULL;
    long lopt;
    int negate;
    *options = SSL_OP_ALL;
    sopt = strtok_r(stroptions, "|", &next);
    while (sopt) {
        std::cout << sopt << "\n";
        if (*sopt == '!') {
            negate = 1;
            sopt++;
        } else
            negate = 0;
        if (!(lopt = openssl_option(sopt))) {
            free(stroptions);
            return 0;
        }
        if (negate)
            *options ^= lopt;
        else
            *options |= lopt;
        sopt = strtok_r(NULL, "|", &next);
    }
    free(stroptions);
    return 1;
}

static std::map<int, const char *> TlsVersionsTable = {
    {0x0304, "TLSv1.3"},
    {0x0303, "TLSv1.2"},
    {0x0302, "TLSv1.1"},
    {0x0301, "TLSv1.0"},
    {0x0300, "SSLv3"},
};

uint16_t tlsVersionHex(const char *version)
{
    for (const auto &v: TlsVersionsTable) {
        if (strcmp(version, v.second) == 0)
            return v.first;
    }
    return 0;
}

const char *tlsVersionToString(uint16_t version)
{
    const auto &v = TlsVersionsTable.find(version);
    if (v != TlsVersionsTable.end())
        return v->second;
    return nullptr;
}

int upToTlsVersion(SSL_CTX *ctx, const char *method_str)
{
    if ( 0 == strcasecmp(method_str, "SSLv23")) {
        SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }
    else if ( 0 == strcasecmp(method_str, "TLSv1_3") || 0 == strcasecmp(method_str, "TLSv1.3") ) {
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }
    else if ( 0 == strcasecmp(method_str, "TLSv1_2") || 0 == strcasecmp(method_str, "TLSv1.2") ) {
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }
    else if ( 0 == strcasecmp(method_str, "TLSv1_1") || 0 == strcasecmp(method_str, "TLSv1.1") ) {
        SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }
    else if ( 0 == strcasecmp(method_str, "TLSv1")) {
        SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }
    else
        return 0;
    return 1;
}

int setSupportedVersions(SSL_CTX *ctx, const std::vector<uint16_t> &versions)
{
    uint16_t min = 0x0304;
    uint16_t max = 0x0301;
    for (const auto v: versions) {
        if (min > v)
            min = v;
        if (max < v)
            max = v;
    }

    if (min > max) min = max;
    if (min < TLS1_VERSION) min = TLS1_VERSION;
    if (max > TLS1_3_VERSION) max = TLS1_3_VERSION;

    SSL_CTX_set_max_proto_version(ctx, max);
    SSL_CTX_set_min_proto_version(ctx, min);
    return 1;
}

int TLS_set_version_option(const char *method_str, long *options)
{
    long method_options = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    if ( 0 == strcmp(method_str, "SSLv23")) {
        method_options = SSL_OP_NO_TLSv1
#if defined(SSL_OP_NO_TLSv1_1)
            | SSL_OP_NO_TLSv1_1
#endif
#if defined(SSL_OP_NO_TLSv1_2)
            | SSL_OP_NO_TLSv1_2
#endif
#if defined(SSL_OP_NO_TLSv1_3)
            | SSL_OP_NO_TLSv1_3
#endif
            ;
    }
#endif
#if defined(SSL_OP_NO_TLSv1_3) /* TLSv1.3 is supported */
    else if ( 0 == strcmp(method_str, "TLSv1_3")) {
        method_options = SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2
#if defined(SSL_OP_NO_TLSv1_1)
            | SSL_OP_NO_TLSv1_1
#endif
#if defined(SSL_OP_NO_TLSv1_2)
            | SSL_OP_NO_TLSv1_2
#endif
            ;
    }
#endif
#if defined(SSL_OP_NO_TLSv1_2) /* TLSv1.2 is supported */
    else if ( 0 == strcmp(method_str, "TLSv1_2")) {
        method_options = SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2
#if defined(SSL_OP_NO_TLSv1_1)
            | SSL_OP_NO_TLSv1_1
#endif
#if defined(SSL_OP_NO_TLSv1_3)
            | SSL_OP_NO_TLSv1_3
#endif
            ;
    }
#endif
#if defined(SSL_OP_NO_TLSv1_1) /* TLSv1.1 is supported */
    else if ( 0 == strcmp(method_str, "TLSv1_1")) {
        method_options = SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2
#if defined(SSL_OP_NO_TLSv1_2)
            | SSL_OP_NO_TLSv1_2
#endif
#if defined(SSL_OP_NO_TLSv1_3)
            | SSL_OP_NO_TLSv1_3
#endif
            ;
    }
#endif
    else if ( 0 == strcmp(method_str, "TLSv1")) {
        method_options = SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2
#if defined(SSL_OP_NO_TLSv1_1)
            | SSL_OP_NO_TLSv1_1
#endif
#if defined(SSL_OP_NO_TLSv1_2)
            | SSL_OP_NO_TLSv1_2
#endif
#if defined(SSL_OP_NO_TLSv1_3)
            | SSL_OP_NO_TLSv1_3
#endif
            ;
    }
#ifndef OPENSSL_NO_SSL3_METHOD
    else if ( 0 == strcmp(method_str, "SSLv3")) {
        method_options = SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2
#if defined(SSL_OP_NO_TLSv1_1)
            | SSL_OP_NO_TLSv1_1
#endif
#if defined(SSL_OP_NO_TLSv1_2)
            | SSL_OP_NO_TLSv1_2
#endif
#if defined(SSL_OP_NO_TLSv1_3)
            | SSL_OP_NO_TLSv1_3
#endif
            ;
    }
#endif
    else {
        return 0;
    }
    *options |= method_options;
    return 1;
}

bool TlsClientSettings::parseCiphers(std::string &list)
{
    ciphers = list;
    return true;
}

bool TlsClientSettings::parseVersion(std::string &ver)
{
    if (ver.empty())
        return true;

    max_version = ver;

    if (tlsVersionHex(ver.c_str()) == 0) {
        DEBUG(5, "Wrong TLS version: " << ver);
        return false;
    }

    // TODO: check if it is valid
    return true;
}

bool TlsClientSettings::parseOptions(std::string &opts)
{
    options = opts;
    return true;
}
int app_settings_add_cb(SSL *s, unsigned int ext_type,
                        const unsigned char **out,
                        size_t *outlen, int *al,
                        void *add_arg)
{
    std::vector<uint8_t> *varg = (std::vector<uint8_t> *) add_arg;
    if (!varg)
        return 0;

    *out = varg->data();
    *outlen = varg->size();
    return 1;
}


void library_settings(SSL_CTX *ctx, const TlsClientSettings &settings)
{
    std::string ciphers = settings.ciphers;
    // This is required to allow use unsafe options while mimicking
    // various clients
    if (!ciphers.empty()) {
        ciphers.append(":");
        ciphers.append("@SECLEVEL=1");
    } else
        ciphers.append("DEFAULT:@SECLEVEL=1");

    if (!ciphers.empty())
        SSL_CTX_set_cipher_list(ctx, ciphers.c_str());
    if (!settings.cipher_suites.empty())
        SSL_CTX_set_ciphersuites(ctx, settings.cipher_suites.c_str());

#if 0
    if (!settings.applicationSettingsRaw.empty()) {
        SSL_CTX_add_client_custom_ext(ctx,
                                      17513,
                                      app_settings_add_cb,
                                      app_settings_free_cb,
                                      (void *)&settings.applicationSettingsRaw,
                                      app_settings_parse_cb,
                                      nullptr);
    }
#endif
}

void SSL_library_settings(SSL *ssl, const TlsClientSettings &settings)
{
    if (settings.status_request)
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
}

void xxx_ssl_configure_SSL_CTX(SSL_CTX *ctx, const TlsClientSettings &settings)
{
    // Set options:
    long options = 0;
    if (settings.supported_versions.size()) {
        setSupportedVersions(ctx, settings.supported_versions);
    } else if (settings.max_version.size()) {
        upToTlsVersion(ctx, settings.max_version.c_str());
    }
    if (settings.options.size()) {
        if (!TLS_parse_options(settings.options.c_str(), &options)) {
            DEBUG(5, "Error parsing TLS options: " << settings.options);
            // Ignore
        }
    }

    if (options)
        SSL_CTX_set_options(ctx, options);

#if 0
    // The following is not enough to add pre_shared_key extension.
    // TODO: check what required to add it even if the offered key
    // is not valid.
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SSL_CTX_set_tlsext_ticket_key_cb(ctx, RenewTicketCallback);
#else
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, RenewTicketCallback);
#endif
#endif

    library_settings(ctx, settings);
}

void xxx_ssl_configure_SSL(SSL *ssl, const TlsClientSettings &settings)
{
    if (settings.sni.length())
        SSL_set_tlsext_host_name(ssl, settings.sni.c_str());
    if (settings.tlsAppLayerProtoNeg.length())
        SSL_set_alpn_protos(ssl, (unsigned char *)settings.tlsAppLayerProtoNeg.data(), settings.tlsAppLayerProtoNeg.length());
    SSL_library_settings(ssl, settings);
    if (!settings.signatureAlgorithsCert.empty())
        SSL_set1_sigalgs_list(ssl, settings.signatureAlgorithsCert.c_str());
}


// Copied and adapted from chromium.
static int bio_string_write(BIO* bio, const char* data, int len)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    reinterpret_cast<std::string*>(bio->ptr)->append(data, len);
#else
    reinterpret_cast<std::string*>(BIO_get_data(bio))->append(data, len);
#endif
    return len;
}

static int bio_string_puts(BIO* bio, const char* data)
{
    // Note: unlike puts(), BIO_puts does not add a newline.
    return bio_string_write(bio, data, strlen(data));
}

static long bio_string_ctrl(BIO* bio, int cmd, long num, void* ptr)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    std::string* str = reinterpret_cast<std::string*>(bio->ptr);
#else
    std::string* str = reinterpret_cast<std::string*>(BIO_get_data(bio));
#endif
    switch (cmd) {
    case BIO_CTRL_RESET:
        str->clear();
        return 1;
    case BIO_C_FILE_SEEK:
        return -1;
    case BIO_C_FILE_TELL:
        return str->size();
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}

static int bio_string_new(BIO* bio)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    bio->ptr = NULL;
    bio->init = 0;
#else
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
#endif
    return 1;
}

static int bio_string_free(BIO* bio) {
    // The string is owned by the caller, so there's nothing to do here.
    return bio != NULL;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static BIO_METHOD bio_string_methods = {
    BIO_TYPE_SOURCE_SINK,
    "bio_string",
    bio_string_write,
    NULL, /* read */
    bio_string_puts,
    NULL, /* gets */
    bio_string_ctrl,
    bio_string_new,
    bio_string_free,
    NULL, /* callback_ctrl */
};
static BIO_METHOD *bio_string_methods_ptr = &bio_string_methods;
#else
static BIO_METHOD *bio_string_methods_ptr = nullptr;
#endif

static BIO* BIO_new_string(std::string* out)
{
    BIO* bio = BIO_new(bio_string_methods_ptr);
    if (!bio)
        return bio;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    bio->ptr = out;
    bio->init = 1;
#else
    BIO_set_data(bio, out);
    BIO_set_init(bio, 1);
#endif
    return bio;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static bool BIO_set_string(BIO &bio, std::string &out)
{
    if (!BIO_set(&bio, bio_string_methods_ptr))
        return false;

    bio.ptr = &out;
    bio.init = 1;
    return true;
}
#endif


void tlsInit()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    OPENSSL_no_config();

#if (OPENSSL_VERSION_NUMBER > 0x10100000L)
    bio_string_methods_ptr = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Squid-SBuf");
    BIO_meth_set_write(bio_string_methods_ptr, bio_string_write);
    BIO_meth_set_read(bio_string_methods_ptr, nullptr);
    BIO_meth_set_puts(bio_string_methods_ptr, bio_string_puts);
    BIO_meth_set_gets(bio_string_methods_ptr, nullptr);
    BIO_meth_set_ctrl(bio_string_methods_ptr, bio_string_ctrl);
    BIO_meth_set_create(bio_string_methods_ptr, bio_string_new);
    BIO_meth_set_destroy(bio_string_methods_ptr, bio_string_free);
#endif
}

void tlsDown()
{
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    FIPS_mode_set(0);
#endif
#if !defined(OPENSSL_IS_BORINGSSL)
    CONF_modules_unload(1);
    CONF_modules_free();
#endif
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

#if 0

int main(int argc, char** argv)
{

    tlsInit();


    tlsDown();

    return 0;
}
#endif

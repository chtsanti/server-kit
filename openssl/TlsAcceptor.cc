#include "openssl/TlsAcceptor.h"
#include "Config.h"
#include "Bio.h"

MEMPOOL_IMPLEMENT(TlsAcceptor)

std::string ServerTlsCertPath;
std::string ServerTlsKeyPath;

TlsAcceptor::TlsAcceptor(int clientFd, const struct sockaddr_storage *remote_address):
    client(clientFd, remote_address),
    tlsAcceptCall(&client, this, &TlsAcceptor::tlsAccept)
{
    init();
    DEBUG(5, "TlsAcceptor " << this << " client " << client);
}

    TlsAcceptor::~TlsAcceptor()
{
    DEBUG(5, "TlsAcceptor " << this << " is released");
}

void TlsAcceptor::init()
{
}

void TlsAcceptor::start()
{
    client.needsRead(&tlsAcceptCall);
}

bool TlsAcceptor::done()
{
    if (client.closed())
        return true; // nothing to do
    return false;
}

void TlsAcceptor::shutdown()
{
    DEBUG(5, "Tunneler " << this << " shutdowns client:" << client);
//    if (sessLog.get()) {
//        if (client.closeReason)
//            sessLog->clientSideDetails.closingReason = client.closeReason;
//    }
}


void TlsAcceptor::tlsAccept(const Connection *c, short event)
{
    DEBUG(5, "TlsAcceptor " << this << " connection " << c);
    assert(c == &client);
    if(client.closed())
        return;

    if (event & EV_TIMEOUT) {
        DEBUG(2, client << " " << " tlsAccept timeout, close" );
        client.close("TlsAcceptor::tlsAccept timeout");
        return;
    }

    if (!client.ssl) {
//        clock_gettime (CLOCK_REALTIME, &sessLog->tunnelerLogs.tlsAcceptStart);
        const SSL_METHOD *method = TLS_server_method();
        static SSL_CTX *ctx = nullptr;
        if (!ctx) {
            ctx = SSL_CTX_new(method);
            SSL_CTX_set_default_verify_paths(ctx);
//            SSL_CTX_set_alpn_select_cb(ctx, set_alpn_cb, nullptr);
            //SSL_CTX_use_certificate_chain_file(ctx, ServerTlsCertPath.c_str());
            SSL_CTX_use_certificate_chain_file(ctx, TlsSignCertPath.c_str());
            SSL_CTX_use_PrivateKey_file(ctx, ServerTlsKeyPath.c_str(), SSL_FILETYPE_PEM);
            SSL_CTX_up_ref(ctx);
        }
        client.ssl = SSL_new(ctx);
        SSL_CTX_up_ref(ctx);
        BIO *bio = TunnelBio::Create(client.fd);
        SSL_set_bio(client.ssl, bio, bio);
        SSL_set_accept_state(client.ssl);
        SSL_CTX_free(ctx); //client.ssl also holds a refcount
    }

    int ret = Connection::TLS_Accept(client, &tlsAcceptCall);
    if (!ret)
        return; // retry.
    if (ret < 0)
        client.close("TlsAcceptor::tlsAccept error");
    tlsAcceptDone();
}

void TlsAcceptor::tlsAcceptDone()
{
    DEBUG(5, "TlsAcceptor " << this);

    //TODO:
    // call callback
}

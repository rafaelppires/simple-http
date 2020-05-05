#pragma once
#include <openssl/ssl.h>

//------------------------------------------------------------------------------
class TlsConnection : public EndpointConnection {
   public:
    virtual ~TlsConnection();
    TlsConnection() : ssl_(nullptr) {}
    bool connect(const std::string &host, int port);
    int send(const char *buff, size_t len);
    int recv(char *buff, size_t len);
    void close();

   private:
    SSL *ssl_;
    static const char *sslerr_str(int e);
    static int password_cb(char *buf, int size, int rwflag, void *password);
    static EVP_PKEY *generatePrivateKey();
    static X509 *generateCertificate(EVP_PKEY *pkey);
    static SSL_CTX *create_context();
    static void configure_context(SSL_CTX *ctx);
    static void init_openssl(SSL_CTX **ctx);
    static SSL_CTX *context;
};

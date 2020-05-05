//------------------------------------------------------------------------------
// TLS CONNECTION
//------------------------------------------------------------------------------
SSL_CTX *TlsConnection::context = 0;
//------------------------------------------------------------------------------
TlsConnection::~TlsConnection() { close(); }

//------------------------------------------------------------------------------
void TlsConnection::close() {
    if (ssl_ != nullptr) {
        // SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    EndpointConnection::close();
}

//------------------------------------------------------------------------------
const char *TlsConnection::sslerr_str(int e) {
    static char buff[100] = {0};
    switch (e) {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
        default:
            strncpy(buff, (std::to_string(e) + ": UNKKNOWN").c_str(),
                    sizeof(buff) - 1);
            return buff;
    };
}

//------------------------------------------------------------------------------
int TlsConnection::password_cb(char *buf, int size, int rwflag,
                               void *password) {
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

//------------------------------------------------------------------------------
EVP_PKEY *TlsConnection::generatePrivateKey() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

//------------------------------------------------------------------------------
X509 *TlsConnection::generateCertificate(EVP_PKEY *pkey) {
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (const unsigned char *)"CH", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"A-SKY", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());
    return x509;
}

//------------------------------------------------------------------------------
SSL_CTX *TlsConnection::create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

//------------------------------------------------------------------------------
void TlsConnection::configure_context(SSL_CTX *ctx) {
    EVP_PKEY *pkey = generatePrivateKey();
    X509 *x509 = generateCertificate(pkey);

    SSL_CTX_use_certificate(ctx, x509);
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

//------------------------------------------------------------------------------
void TlsConnection::init_openssl(SSL_CTX **ctx) {
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
    SSL_load_error_strings();

    *ctx = create_context();
    SSL_CTX_set_ecdh_auto(*ctx, 1);
    configure_context(*ctx);
}

//------------------------------------------------------------------------------
bool TlsConnection::connect(const std::string &host, int port) {
    if (context == 0) init_openssl(&context);
    socket = getsocket(host, port);
    if (socket > 0) {
        SSL *cli = SSL_new(context);
        SSL_set_fd(cli, socket);
        ERR_clear_error();
        int r = SSL_connect(cli);
        if (r == 0) {
            printf("%s\n", ERR_error_string(ERR_get_error(), nullptr));
            return false;
        }

        if (r < 0) {
            SSL_free(cli);
            printf("%s: %s\n", sslerr_str(SSL_get_error(cli, r)),
                   ERR_error_string(ERR_get_error(), nullptr));
            close();
            return false;
        }
        ssl_ = cli;
        return true;
    }
    return false;
}

//------------------------------------------------------------------------------
int TlsConnection::send(const char *buff, size_t len) {
    if (ssl_ == nullptr) return -1;
    return SSL_write(ssl_, buff, len);
}

//------------------------------------------------------------------------------
int TlsConnection::recv(char *buff, size_t len) {
    if (ssl_ == nullptr) return -1;
    int ret = SSL_read(ssl_, buff, len);
    if (ret <= 0)
        printf("SSL_read error: %s\n", sslerr_str(SSL_get_error(ssl_, ret)));
    return ret;
}

//------------------------------------------------------------------------------
bool EndpointConnection::connect(EndpointConnection **endpoint,                 
                                 const HttpUrl &url) {                          
    if (url.isHttps()) {                                                        
        *endpoint = new TlsConnection();                                        
    } else {                                                                    
        *endpoint = new PlainConnection();                                      
    }                                                                           
                                                                                
    if (!(*endpoint)->connect(url.host(), url.port())) {                        
        delete *endpoint;                                                       
        *endpoint = nullptr;                                                    
        return false;                                                           
    }                                                                           
    return true;                                                                
}                                                                               
                                                                                
//------------------------------------------------------------------------------

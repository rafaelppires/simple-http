#pragma once

#ifdef ENCLAVED
#include <libc_mock/libc_proxy.h>
#endif
#include <httpurl.h>

#include <string>
#ifdef ENCLAVED
#undef connect
#endif

//------------------------------------------------------------------------------
class EndpointConnection {
   public:
    virtual ~EndpointConnection() {}
    virtual int send(const char *buff, size_t len) = 0;
    virtual int recv(char *buff, size_t len) = 0;
    virtual bool connect(const std::string &host, int port) = 0;
    virtual void close();

    static bool connect(EndpointConnection **endpoint, const HttpUrl &url);

   protected:
    int getsocket(const std::string &host, int port);
    int socket;
};

//------------------------------------------------------------------------------
class PlainConnection : public EndpointConnection {
   public:
    virtual ~PlainConnection();
    bool connect(const std::string &host, int port);
    int send(const char *buff, size_t len);
    template <typename T>
    int send(const T &data) {
        return send(data.data(), data.size());
    }
    int recv(char *buff, size_t len);
};

//------------------------------------------------------------------------------

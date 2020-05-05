#include <errno.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/socket.h>
#include <tcpconnection.h>
#include <unistd.h>
#ifdef ENCLAVED
#include <inet_pton_ntop.h>
#include <my_wrappers.h>
#define htons(n) \
    (((((unsigned short)(n)&0xFF)) << 8) | (((unsigned short)(n)&0xFF00) >> 8))
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#endif

//------------------------------------------------------------------------------
// PLAIN CONNECTION
//------------------------------------------------------------------------------
PlainConnection::~PlainConnection() { close(); }

//------------------------------------------------------------------------------
bool PlainConnection::connect(const std::string &host, int port) {
    socket = getsocket(host, port);
    return socket > 0;
}

//------------------------------------------------------------------------------
int PlainConnection::send(const char *buff, size_t len) {
    return ::send(socket, buff, len, 0);
}

//------------------------------------------------------------------------------
int PlainConnection::recv(char *buff, size_t len) {
    return ::recv(socket, buff, len, 0);
}

//------------------------------------------------------------------------------
// ENDPOINT CONNECTION
//------------------------------------------------------------------------------
int EndpointConnection::getsocket(const std::string &host, int port) {
    struct sockaddr_in address;
    int sock = 0;

    struct addrinfo *res, *it;
    int errorcode;
    if ((errorcode = getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                                 nullptr, &res))) {
        printf("Address resolution error %d: '%s'\n", errorcode, host.c_str());
        return -1;
    }

    for (it = res; it != nullptr; it = it->ai_next) {
        if ((sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol)) <
            0) {
            printf("Error getting socket: %d\n", errno);
            continue;
        }

        if (::connect(sock, it->ai_addr, it->ai_addrlen) < 0) {
            ::close(sock);
            perror("TCP Connection failed");
            continue;
        }
        break;
    }

    return it == nullptr ? -2 : sock;
}

//------------------------------------------------------------------------------
void EndpointConnection::close() {
    if (socket > 0) ::close(socket);
    socket = -1;
}

//------------------------------------------------------------------------------

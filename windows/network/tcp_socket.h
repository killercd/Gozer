#ifndef _WIN_TCP_SOCKET_
#define _WIN_TCP_SOCKET_

#include <winsock2.h>
#include <string>

#ifdef STATUS_TIMEOUT
#undef STATUS_TIMEOUT
#endif

class TcpClientSocket
{

    private:
        std::string host;
        int port;
        SOCKET sockFd;
        int sockStatus;
        bool winsockReady;

    public:
        enum SocketStatus
        {
            STATUS_DISCONNECTED = 0,
            STATUS_CONNECTED = 1,
            STATUS_INVALID_ENDPOINT = -1,
            STATUS_DNS_ERROR = -2,
            STATUS_CONNECT_ERROR = -3,
            STATUS_SEND_ERROR = -4,
            STATUS_RECV_ERROR = -5,
            STATUS_REMOTE_CLOSED = -6,
            STATUS_TIMEOUT = -7,
            STATUS_OPTION_ERROR = -8
        };

        TcpClientSocket();
        TcpClientSocket(const std::string &host, int port);
        virtual ~TcpClientSocket();

        virtual bool connect(int timeoutMs = -1);
        virtual bool connect(const std::string &host, int port, int timeoutMs = -1);
        virtual bool send(const std::string &data, int timeoutMs = -1);
        virtual std::string recv(int maxBytes = 4096, int timeoutMs = -1);
        virtual int status();
        virtual bool close();
};

#endif

#include "tcp_socket.h"

#include <stdio.h>
#include <string.h>

#include <ws2tcpip.h>

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

namespace
{
    int g_winsockUsers = 0;

    bool acquireWinsock()
    {
        if(g_winsockUsers > 0)
        {
            ++g_winsockUsers;
            return true;
        }

        WSADATA wsaData;
        if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            return false;

        g_winsockUsers = 1;
        return true;
    }

    void releaseWinsock()
    {
        if(g_winsockUsers <= 0)
            return;

        --g_winsockUsers;
        if(g_winsockUsers == 0)
            WSACleanup();
    }

    bool isValidEndpoint(const std::string &host, int port)
    {
        return !host.empty() && port > 0 && port <= 65535;
    }

    bool isTimeoutError(int code)
    {
        return code == WSAEWOULDBLOCK || code == WSAETIMEDOUT;
    }

    bool setSocketTimeout(SOCKET fd, int option, int timeoutMs)
    {
        if(timeoutMs < 0)
            return true;

        const DWORD value = (DWORD)timeoutMs;
        return setsockopt(fd, SOL_SOCKET, option, (const char *)&value, sizeof(value)) == 0;
    }

    bool readCurrentTimeout(SOCKET fd, int option, DWORD &out)
    {
        int len = (int)sizeof(out);
        return getsockopt(fd, SOL_SOCKET, option, (char *)&out, &len) == 0;
    }

    void restoreTimeoutIfNeeded(SOCKET fd, int option, bool hasPrevious, DWORD previous)
    {
        if(!hasPrevious)
            return;

        (void)setsockopt(fd, SOL_SOCKET, option, (const char *)&previous, sizeof(previous));
    }

    bool setNonBlocking(SOCKET fd, bool enabled)
    {
        u_long mode = enabled ? 1UL : 0UL;
        return ioctlsocket(fd, FIONBIO, &mode) == 0;
    }

    bool connectWithTimeout(SOCKET fd, const struct sockaddr *addr, int addrLen, int timeoutMs, bool &timedOut)
    {
        timedOut = false;

        if(timeoutMs < 0)
            return ::connect(fd, addr, addrLen) == 0;

        if(!setNonBlocking(fd, true))
            return false;

        int ret = ::connect(fd, addr, addrLen);
        if(ret == 0)
        {
            (void)setNonBlocking(fd, false);
            return true;
        }

        const int lastError = WSAGetLastError();
        if(lastError != WSAEWOULDBLOCK && lastError != WSAEINPROGRESS && lastError != WSAEINVAL)
        {
            (void)setNonBlocking(fd, false);
            return false;
        }

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(fd, &writeSet);

        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        ret = select(0, NULL, &writeSet, NULL, &tv);
        if(ret == 0)
        {
            timedOut = true;
            (void)setNonBlocking(fd, false);
            return false;
        }

        if(ret < 0)
        {
            (void)setNonBlocking(fd, false);
            return false;
        }

        int soError = 0;
        int soLen = (int)sizeof(soError);
        if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soError, &soLen) != 0)
        {
            (void)setNonBlocking(fd, false);
            return false;
        }

        (void)setNonBlocking(fd, false);
        if(soError == WSAETIMEDOUT)
            timedOut = true;

        return soError == 0;
    }
}

TcpClientSocket::TcpClientSocket()
{
    host = "";
    port = 0;
    sockFd = INVALID_SOCKET;
    sockStatus = STATUS_DISCONNECTED;
    winsockReady = acquireWinsock();
}

TcpClientSocket::TcpClientSocket(const std::string &host, int port)
{
    this->host = host;
    this->port = port;
    sockFd = INVALID_SOCKET;
    sockStatus = STATUS_DISCONNECTED;
    winsockReady = acquireWinsock();
}

TcpClientSocket::~TcpClientSocket()
{
    close();

    if(winsockReady)
    {
        releaseWinsock();
        winsockReady = false;
    }
}

bool TcpClientSocket::connect(int timeoutMs)
{
    close();

    if(!winsockReady)
    {
        sockStatus = STATUS_CONNECT_ERROR;
        return false;
    }

    if(!isValidEndpoint(host, port))
    {
        sockStatus = STATUS_INVALID_ENDPOINT;
        return false;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portBuffer[16];
    snprintf(portBuffer, sizeof(portBuffer), "%d", port);

    const int gaiRet = getaddrinfo(host.c_str(), portBuffer, &hints, &result);
    if(gaiRet != 0 || result == NULL)
    {
        sockStatus = STATUS_DNS_ERROR;
        return false;
    }

    bool connected = false;
    bool timedOut = false;

    for(rp = result; rp != NULL; rp = rp->ai_next)
    {
        const SOCKET fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == INVALID_SOCKET)
            continue;

        bool currentTimedOut = false;
        if(connectWithTimeout(fd, rp->ai_addr, (int)rp->ai_addrlen, timeoutMs, currentTimedOut))
        {
            sockFd = fd;
            connected = true;
            break;
        }

        if(currentTimedOut)
            timedOut = true;

        closesocket(fd);
    }

    freeaddrinfo(result);

    if(!connected)
    {
        sockStatus = timedOut ? STATUS_TIMEOUT : STATUS_CONNECT_ERROR;
        return false;
    }

    sockStatus = STATUS_CONNECTED;
    return true;
}

bool TcpClientSocket::connect(const std::string &host, int port, int timeoutMs)
{
    this->host = host;
    this->port = port;
    return connect(timeoutMs);
}

bool TcpClientSocket::send(const std::string &data, int timeoutMs)
{
    if(sockFd == INVALID_SOCKET)
    {
        sockStatus = STATUS_DISCONNECTED;
        return false;
    }

    const int totalSize = (int)data.size();
    if(totalSize <= 0)
        return true;

    const char *buffer = data.c_str();
    int totalSent = 0;
    DWORD previousTimeout = 0;
    bool hasPreviousTimeout = false;

    if(timeoutMs >= 0)
    {
        hasPreviousTimeout = readCurrentTimeout(sockFd, SO_SNDTIMEO, previousTimeout);
        if(!setSocketTimeout(sockFd, SO_SNDTIMEO, timeoutMs))
        {
            sockStatus = STATUS_OPTION_ERROR;
            return false;
        }
    }

    while(totalSent < totalSize)
    {
        const int bytes = ::send(sockFd, buffer + totalSent, totalSize - totalSent, 0);

        if(bytes == SOCKET_ERROR)
        {
            const int lastError = WSAGetLastError();

            if(lastError == WSAEINTR)
                continue;

            restoreTimeoutIfNeeded(sockFd, SO_SNDTIMEO, hasPreviousTimeout, previousTimeout);
            sockStatus = isTimeoutError(lastError) ? STATUS_TIMEOUT : STATUS_SEND_ERROR;
            return false;
        }

        if(bytes == 0)
        {
            restoreTimeoutIfNeeded(sockFd, SO_SNDTIMEO, hasPreviousTimeout, previousTimeout);
            close();
            sockStatus = STATUS_REMOTE_CLOSED;
            return false;
        }

        totalSent += bytes;
    }

    restoreTimeoutIfNeeded(sockFd, SO_SNDTIMEO, hasPreviousTimeout, previousTimeout);
    sockStatus = STATUS_CONNECTED;
    return true;
}

std::string TcpClientSocket::recv(int maxBytes, int timeoutMs)
{
    std::string result;

    if(sockFd == INVALID_SOCKET)
    {
        sockStatus = STATUS_DISCONNECTED;
        return result;
    }

    if(maxBytes <= 0)
    {
        sockStatus = STATUS_RECV_ERROR;
        return result;
    }

    std::vector<char> buffer(maxBytes);
    int bytes = 0;
    DWORD previousTimeout = 0;
    bool hasPreviousTimeout = false;

    if(timeoutMs >= 0)
    {
        hasPreviousTimeout = readCurrentTimeout(sockFd, SO_RCVTIMEO, previousTimeout);
        if(!setSocketTimeout(sockFd, SO_RCVTIMEO, timeoutMs))
        {
            sockStatus = STATUS_OPTION_ERROR;
            return result;
        }
    }

    do
    {
        bytes = ::recv(sockFd, buffer.data(), maxBytes, 0);
    } while(bytes == SOCKET_ERROR && WSAGetLastError() == WSAEINTR);

    if(bytes > 0)
    {
        result.assign(buffer.data(), bytes);
        restoreTimeoutIfNeeded(sockFd, SO_RCVTIMEO, hasPreviousTimeout, previousTimeout);
        sockStatus = STATUS_CONNECTED;
        return result;
    }

    if(bytes == 0)
    {
        restoreTimeoutIfNeeded(sockFd, SO_RCVTIMEO, hasPreviousTimeout, previousTimeout);
        close();
        sockStatus = STATUS_REMOTE_CLOSED;
        return result;
    }

    const int lastError = WSAGetLastError();
    restoreTimeoutIfNeeded(sockFd, SO_RCVTIMEO, hasPreviousTimeout, previousTimeout);
    sockStatus = isTimeoutError(lastError) ? STATUS_TIMEOUT : STATUS_RECV_ERROR;
    return result;
}

int TcpClientSocket::status()
{
    return sockStatus;
}

bool TcpClientSocket::close()
{
    if(sockFd != INVALID_SOCKET)
    {
        shutdown(sockFd, SD_BOTH);
        closesocket(sockFd);
        sockFd = INVALID_SOCKET;
    }

    sockStatus = STATUS_DISCONNECTED;
    return true;
}

/*
 * @file        httpserver.h
 * @brief       A single-file header of HTTP server
 * @details     This is a project for Computer Network course in ZJU
 * @author      Jiang Xiaochong
 * @date        11/5/2019
 * @version     1.0.1
 * @par         Copyright(c): Jiang Xiaochong
 */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // _CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif // _CRT_NONSTDC_NO_DEPRECATE

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif // strcasecmp

typedef SOCKET socket_t;
#else
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int socket_t;
#define INVALID_SOCKET (-1)
#endif // _WIN32

#include "console.h"
#include <assert.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <thread>

/* Winsock initialization */
#ifdef _WIN32
class WinsockInit
{
public:
    WinsockInit()
    {
        WSADATA wsaData;
        int err = WSAStartup(0x0202, &wsaData);
        if (err != 0)
        {
            Console.printRedText("WSAStartup failed with error: %d\n", err);
            exit(0);
        };

        if (wsaData.wVersion != 0x0202)
        {
            Console.printRedText("Could not find a usable version of Winsock.dll\n");
            WSACleanup();
            exit(0);
        }
    }

    ~WinsockInit() { WSACleanup(); }
};

static WinsockInit wsinit;
#endif

/* Some utility functions */
namespace Utils
{

// A function template to create socket at specific address:port
template <typename Fn>
socket_t createSocket(const char *host, int port, Fn fn, int socket_flags = 0);

// A function to close specific socket, resolving API name conflict
int closeSocket(socket_t sock);

// A function to check specific socket's status
int selectSocket(socket_t sock, time_t sec, time_t usec);

// Get the remote/local address associated to specific socket
template <typename Fn>
std::string getSocketAddress(socket_t sock, Fn fn);

// A string comparator
struct strcmptor
{
    bool operator()(const std::string &s1, const std::string &s2) const
    {
        return std::lexicographical_compare(
            s1.begin(), s1.end(), s2.begin(), s2.end(),
            [](char c1, char c2) { return ::tolower(c1) < ::tolower(c2); });
    }
};

// A safer function to find substring
char *findSubStr(const std::vector<char> &buf, const char *s, size_t pos = 0);

// Sick of Linux compiler not use it as "int"
typedef std::ios::openmode mode_t;

// A function to read file
bool loadFile(const char *fp, std::vector<char> &buf,
              mode_t mode = std::ios::binary);

// A function to map status message string
const char *statusMessage(int status);

} // namespace Utils

namespace HttpServer
{
/* Constants */
constexpr int DEFAULT_BUF_SIZE = 8192;

/* Type definitions */
typedef std::multimap<std::string, std::string, Utils::strcmptor> Headers;

/* Declarations */
struct Request
{
    std::string version;
    std::string method;
    std::string target;
    std::string path;
    Headers headers;
    std::string body;
    std::smatch matches;

    bool hasHeader(const char *key) const;
    std::string getHeaderValue(const char *key, size_t id = 0);
    void setHeader(const char *key, const char *val);
};

struct Response
{
    std::string version;
    int status = 404;
    Headers headers;
    std::string body;

    bool hasHeader(const char *key) const;
    std::string getHeaderValue(const char *key, size_t id = 0);
    void setHeader(const char *key, const char *val);

    void setContent(const char *s, size_t n, const char *contentType);
    void setContent(const std::string &s, const char *contentType);
};

class Stream
{
public:
    virtual ~Stream() {}
    virtual int read(char *ptr, size_t size) = 0;
    virtual int write(const char *ptr, size_t size1) = 0;
    virtual int write(const char *ptr) = 0;
    virtual std::string getRemoteAddr() const = 0;
    virtual std::string getLocalAddr() const = 0;

    template <typename... Args>
    void writeFormat(const char *format, const Args &... args);
};

class SocketStream : public Stream
{
public:
    SocketStream(socket_t sock);
    virtual ~SocketStream();

    virtual int read(char *ptr, size_t size);
    virtual int write(const char *ptr, size_t size);
    virtual int write(const char *ptr);
    virtual std::string getRemoteAddr() const;
    virtual std::string getLocalAddr() const;

private:
    socket_t connectSocket;
};

class RequestReader
{
public:
    RequestReader(Stream &strm);

    bool isValid() { return is_valid; }
    bool hasBody() { return has_body; }
    std::string getLine();
    const std::string &getBody() const { return body; }

    void printContent() const;

private:
    int len = 0;
    int pos = 0;
    bool is_valid = true;
    bool has_body = true;

    std::string body;
    std::vector<char> buf;
};

class Server
{
public:
    typedef std::function<void(const Request &, Response &)> Handler;

    Server();

    Server &Get(const char *pattern, Handler handler);
    Server &Post(const char *pattern, Handler handler);

    // Mainloop
    bool start(const char *host, int port, int socket_flags = 0);

private:
    typedef std::vector<std::pair<std::regex, Handler>> Handlers;
    socket_t createServerSocket(const char *host, int port, int socket_flags = 0);

    bool requestHandler(socket_t sock);
    bool processRequest(Stream &strm);

    bool parseRequestLine(RequestReader &reader, Request &req);
    bool parseRequestHeaders(RequestReader &reader, Request &req);

    bool routeResponse(Request &req, Response &res);
    bool dispatchHandler(Request &req, Response &res, Handlers handlers);
    void writeResponse(Stream &strm, Request &req, Response &res);

    bool isRunning;
    socket_t listenSocket;
    Handlers getHandlers;
    Handlers postHandlers;
};

/* Definitions */
inline bool Request::hasHeader(const char *key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Request::getHeaderValue(const char *key, size_t id)
{
    auto it = headers.find(key);
    std::advance(it, id);
    if (it != headers.end())
    {
        return it->second.c_str();
    }
    return "";
}

inline void Request::setHeader(const char *key, const char *val)
{
    headers.emplace(key, val);
}

inline bool Response::hasHeader(const char *key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Response::getHeaderValue(const char *key, size_t id)
{
    auto it = headers.find(key);
    std::advance(it, id);
    if (it != headers.end())
    {
        return it->second.c_str();
    }
    return "";
}

inline void Response::setHeader(const char *key, const char *val)
{
    headers.emplace(key, val);
}

inline void Response::setContent(const char *s, size_t n,
                                 const char *contentType)
{
    body.assign(s, n);
    setHeader("Content-Type", contentType);
}

inline void Response::setContent(const std::string &s,
                                 const char *contentType)
{
    body = s;
    setHeader("Content-Type", contentType);
}

template <typename... Args>
inline void Stream::writeFormat(const char *format, const Args &... args)
{
    const auto bufsiz = 2048;
    char buf[bufsiz];

#if defined(_MSC_VER) && _MSC_VER < 1900
    auto n = _snprintf_s(buf, bufsiz, bufsiz - 1, format, args...);
#else
    auto n = snprintf(buf, bufsiz - 1, format, args...);
#endif
    if (n > 0)
    {
        if (n >= bufsiz - 1)
        {
            std::vector<char> vbuf(bufsiz);

            while (n >= static_cast<int>(vbuf.size() - 1))
            {
                vbuf.resize(vbuf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
                n = _snprintf_s(&vbuf[0], vbuf.size(), vbuf.size() - 1, format,
                                args...);
#else
                n = snprintf(&vbuf[0], vbuf.size() - 1, format, args...);
#endif
            }
            write(&vbuf[0], n);
        }
        else
        {
            write(buf, n);
        }
    }
}

inline SocketStream::SocketStream(socket_t sock) : connectSocket(sock) {}

inline SocketStream::~SocketStream() {}

inline int SocketStream::read(char *ptr, size_t size)
{
    return recv(connectSocket, ptr, static_cast<int>(size), 0);
}

inline int SocketStream::write(const char *ptr, size_t size)
{
    return send(connectSocket, ptr, static_cast<int>(size), 0);
}

inline int SocketStream::write(const char *ptr)
{
    return write(ptr, strlen(ptr));
}

inline std::string SocketStream::getRemoteAddr() const
{
    return Utils::getSocketAddress(
        connectSocket, [](socket_t s, struct sockaddr *n, socklen_t *l) -> int {
            return getpeername(s, n, l);
        });
}

inline std::string SocketStream::getLocalAddr() const
{
    return Utils::getSocketAddress(
        connectSocket, [](socket_t s, struct sockaddr *n, socklen_t *l) -> int {
            return getsockname(s, n, l);
        });
}

inline RequestReader::RequestReader(Stream &strm)
{
    // Resize the buffer
    buf.resize(static_cast<size_t>(DEFAULT_BUF_SIZE));

    // Read to buffer
    len = strm.read(&buf[0], static_cast<size_t>(DEFAULT_BUF_SIZE));
    if (len <= 0)
    {
        is_valid = false;
        has_body = false;
        buf.clear();
    }
    else
    {
        // Check if it has body
        char pattern[] = "\r\n\r\n";
        char *p = Utils::findSubStr(buf, pattern) + 4;
        size_t count = (p - &buf[0]);
        if ((has_body = (count < DEFAULT_BUF_SIZE && count < len)))
        {
            body.assign(p, len - count);
        }
        else
        {
            body = "";
        }
    }
}

inline std::string RequestReader::getLine()
{
    std::string s = "";
    char pattern[] = "\r\n";
    char *p = Utils::findSubStr(buf, pattern, pos);
    if (!p)
    {
        s.append("\n");
    }
    else
    {
        s.append(&buf[pos], (p - &buf[pos]));
        pos += (p - &buf[pos]) + 2;
    }
    return s;
}

inline void RequestReader::printContent() const
{
    std::string content;
    content.assign(&buf[0], len);
    Console.lock();
    Console.printMagentaText(content.c_str());
    Console.unlock();
}

inline Server::Server() : isRunning(false), listenSocket(INVALID_SOCKET) {}

inline bool Server::start(const char *host, int port, int socket_flags)
{
    bool ret = true;

    // Create listening socket
    listenSocket = createServerSocket(host, port, socket_flags);
    if (listenSocket == INVALID_SOCKET)
    {
        Console.printRedText("Failed to create socket!\n");
        return false;
    }
    isRunning = true;

    // Main loop
    for (;;)
    {
        // Use select to implement non-blocking listen
        auto result = Utils::selectSocket(listenSocket, 0, 100000);
        if (result == 0)
        {
            if (listenSocket == INVALID_SOCKET)
            {
                Console.printYellowText("Server closed by STOP!\n");
                break;
            }
            continue;
        }

        // Listen
        socket_t connectSocket = accept(listenSocket, NULL, NULL);
        if (connectSocket == INVALID_SOCKET)
        {
            if (listenSocket != INVALID_SOCKET)
            {
                Console.printRedText("Failed to accept socket!\n");
                Utils::closeSocket(listenSocket);
                ret = false;
            }
            else
            {
                Console.printYellowText("Server closed by user!\n");
            }
            break;
        }

        // Create service thread
        std::thread([=]() {
            // thread to deal with request
            requestHandler(connectSocket);
        })
            .detach();
    }

    // Exit mainloop
    isRunning = false;
    return ret;
}

inline socket_t Server::createServerSocket(const char *host, int port,
                                           int socket_flags)
{
    return Utils::createSocket(
        host, port,
        [](socket_t sock, struct addrinfo &ai) -> bool {
            if (bind(sock, ai.ai_addr, static_cast<int>(ai.ai_addrlen)))
                return false;
            if (listen(sock, 5))
                return false;
            return true;
        },
        socket_flags);
}

inline bool Server::requestHandler(socket_t sock)
{
    // Flags
    bool ret = true;

    // Stream to transfer data
    SocketStream strm = SocketStream(sock);
    Console.lock();
    Console.printGreenText("Thread at %s starts\n", strm.getRemoteAddr().c_str());
    Console.unlock();

    // TODO: Lifetime control
    // Non-blocking receiving data
    while (Utils::selectSocket(sock, 0, 0) > 0)
    {
        ret = processRequest(strm);
    }
    Console.lock();
    Console.printGreenText("Thread at %s exits\n", strm.getRemoteAddr().c_str());
    Console.unlock();
    Utils::closeSocket(sock);
    return ret;
}

inline bool Server::processRequest(Stream &strm)
{
    // Process request data
    RequestReader reader = RequestReader(strm);

    if (reader.isValid() > 0)
    {
        Request req;
        Response res;

        // Parse request line
        if (!parseRequestLine(reader, req))
        {
            // TODO: error handle
        }

        // Parse request headers
        if (!parseRequestHeaders(reader, req))
        {
            // TODO: error handle
        }

        // Parse body
        if (reader.hasBody())
        {
            req.body = reader.getBody();
        }

        // Route
        if (routeResponse(req, res))
        {
        }
        else
        {
            res.status = 404;
        }

        writeResponse(strm, req, res);
    }
    else
    {
        Console.lock();
        Console.printRedText("Failed to receive data!\n");
        Console.unlock();
        return false;
    }
    return true;
}

inline bool Server::parseRequestLine(RequestReader &reader, Request &req)
{
    static std::regex r("(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) "
                        "(([^?]+)(?:\\?(.+?))?) (HTTP/1\\.[01])");

    std::string s = reader.getLine();
    std::cmatch m;
    if (std::regex_match(s.c_str(), m, r))
    {
        req.version = std::string(m[5]);
        req.method = std::string(m[1]);
        req.target = std::string(m[2]);
        req.path = std::string(m[3]);

        // TODO: Parse query text

        return true;
    }
    return false;
}

inline bool Server::parseRequestHeaders(RequestReader &reader, Request &req)
{
    static std::regex r(R"((.+?):\s*(.+?)\s*)");
    std::string requestHeader;

    while ((requestHeader = reader.getLine()) != "")
    {
        std::cmatch m;
        if (std::regex_match(requestHeader.c_str(), m, r))
        {
            auto key = std::string(m[1]);
            auto val = std::string(m[2]);
            req.headers.emplace(key, val);
            continue;
        }
        return false;
    }
    return true;
}

inline bool Server::routeResponse(Request &req, Response &res)
{
    if (req.method == "GET")
        return dispatchHandler(req, res, getHandlers);
    else if (req.method == "POST")
        return dispatchHandler(req, res, postHandlers);

    return false;
}

inline bool Server::dispatchHandler(Request &req, Response &res,
                                    Handlers handlers)
{
    for (const auto &x : handlers)
    {
        const auto &pattern = x.first;
        const auto &handler = x.second;

        if (std::regex_match(req.path, req.matches, pattern))
        {
            handler(req, res);
            return true;
        }
    }
    return false;
}

inline void Server::writeResponse(Stream &strm, Request &req, Response &res)
{
    // Response line
    strm.writeFormat("HTTP/1.1 %d %s\r\n", res.status,
                     Utils::statusMessage(res.status));

    // Headers
    if (req.getHeaderValue("Connection") == "Keep-Alive")
    {
        res.setHeader("Connection", "Keep-Alive");
    }
    if (req.getHeaderValue("Connection") == "close")
    {
        res.setHeader("Connection", "close");
    }
    if (res.body.empty())
    {
        if (!res.hasHeader("Content-Length"))
        {
            res.setHeader("Content-Length", "0");
        }
    }
    else
    {
        if (!res.hasHeader("Content-Type"))
        {
            res.setHeader("Content-Type", "text/plain");
        }
        auto length = std::to_string(res.body.size());
        res.setHeader("Content-Length", length.c_str());
    }
    for (const auto &x : res.headers)
    {
        strm.writeFormat("%s: %s\r\n", x.first.c_str(), x.second.c_str());
    }
    strm.write("\r\n");

    // Body
    if (req.method != "HEAD")
    {
        if (!res.body.empty())
        {
            strm.write(res.body.c_str(), res.body.size());
        }
    }
}

inline Server &Server::Get(const char *pattern, Handler handler)
{
    getHandlers.push_back(std::make_pair(std::regex(pattern), handler));
    return *this;
}

inline Server &Server::Post(const char *pattern, Handler handler)
{
    postHandlers.push_back(std::make_pair(std::regex(pattern), handler));
    return *this;
}

} // namespace HttpServer

template <typename Fn>
inline socket_t Utils::createSocket(const char *host, int port, Fn fn,
                                    int socket_flags)
{
#ifdef _WIN32
#define SO_SYNCHRONOUS_NONALERT 0x20
#define SO_OPENTYPE 0x7008

    int opt = SO_SYNCHRONOUS_NONALERT;
    setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&opt,
               sizeof(opt));
#endif

    // Get address info
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = socket_flags;
    hints.ai_protocol = 0;

    auto service = std::to_string(port);

    if (getaddrinfo(host, service.c_str(), &hints, &result))
    {
        return INVALID_SOCKET;
    }

    for (auto rp = result; rp; rp = rp->ai_next)
    {
        // Create a socket
        auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET)
        {
            continue;
        }

        // Make 'reuse address' option available
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

        // bind or connect
        if (fn(sock, *rp))
        {
            freeaddrinfo(result);
            return sock;
        }

        closeSocket(sock);
    }

    freeaddrinfo(result);
    return INVALID_SOCKET;
}

inline int Utils::closeSocket(socket_t sock)
{
#ifdef _WIN32
    return closesocket(sock);
#else
    return close(sock);
#endif
}

inline int Utils::selectSocket(socket_t sock, time_t sec, time_t usec)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    timeval tv;
    tv.tv_sec = static_cast<long>(sec);
    tv.tv_usec = static_cast<long>(usec);

    return select(static_cast<int>(sock + 1), &fds, NULL, NULL, &tv);
}

template <typename Fn>
inline std::string Utils::getSocketAddress(socket_t sock, Fn fn)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    if (!fn(sock, (struct sockaddr *)&addr, &len))
    {
        int port;
        char ipstr[NI_MAXHOST];

        if (addr.ss_family == AF_INET)
            port = ntohs(reinterpret_cast<struct sockaddr_in *>(&addr)->sin_port);
        else if (addr.ss_family == AF_INET6)
            port = ntohs(reinterpret_cast<struct sockaddr_in6 *>(&addr)->sin6_port);
        else
            return std::string();

        if (!getnameinfo((struct sockaddr *)&addr, len, ipstr, sizeof(ipstr),
                         nullptr, 0, NI_NUMERICHOST))
        {
            return std::string(ipstr) + ":" + std::to_string(port);
        }
    }
    return std::string();
}

inline char *Utils::findSubStr(const std::vector<char> &buf, const char *s,
                               size_t pos)
{
    if (buf.size() == 0 || s == NULL || pos < 0)
        return NULL;
    size_t len = strlen(s);
    for (; pos < buf.size(); pos++)
    {
        if (buf[pos] == *s && !strncmp(&buf[pos], s, len))
            return (char *)(&buf[pos]);
    }
    return NULL;
}

inline bool Utils::loadFile(const char *fp, std::vector<char> &buf,
                            mode_t mode)
{
    std::ifstream fin(fp, mode);
    if (fin.fail())
    {
        return false;
    }
    size_t fl = static_cast<size_t>(fin.seekg(0, std::ios::end).tellg());
    if (fl > buf.size())
        buf.resize(fl);
    fin.seekg(0, std::ios::beg)
        .read(&buf[0], static_cast<std::streamsize>(buf.size()));
    fin.close();
    return true;
}

inline const char *Utils::statusMessage(int status)
{
    switch (status)
    {
    case 200:
        return "OK";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 400:
        return "Bad Request";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 413:
        return "Payload Too Large";
    case 414:
        return "Request-URI Too Long";
    case 415:
        return "Unsupported Media Type";
    default:
    case 500:
        return "Internal Server Error";
    }
}

#endif // HTTP_SERVER_H
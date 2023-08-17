#ifndef NET_PARAMOUT_H_
#define NET_PARAMOUT_H_

#include <memory>
#include <string>
#include <stdexcept>
#include <functional>
#include <cerrno>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#define read recv
typedef SSIZE_T ssize_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace NET
{
    enum class METHOD : std::uint8_t
    {
        GET,
        POST,
        UPDATE,
        DEL
    };

    enum class CODE : std::uint8_t
    {
        OK,
        NOT_FOUND,
        UNAUTHORIZED,
        MALFORMED
    };

    struct Request
    {
        std::uint8_t magic[3]{'N', 'E', 'T'};
        std::uint8_t method{};
        std::uint8_t path[256]{};
        size_t auth_size{};
        size_t body_size{};
        std::unique_ptr<std::uint8_t *> auth;
        std::unique_ptr<std::uint8_t *> body;

        std::shared_ptr<std::uint8_t[]> ToRaw()
        {
            static size_t static_request_size{sizeof(Request) - (sizeof(auth) + sizeof(body))};

            std::shared_ptr<std::uint8_t[]> p_raw(new std::uint8_t[static_request_size]);

            memcpy(p_raw.get(), this, static_request_size + auth_size + body_size);

            if (auth_size != 0)
                memcpy(p_raw.get() + static_request_size, auth.get(), auth_size);

            if (body_size != 0)
                memcpy(p_raw.get() + static_request_size + auth_size, body.get(), body_size);

            return std::move(p_raw);
        }

        static std::shared_ptr<Request> Parse(std::uint8_t *request)
        {
            static size_t static_request_size{sizeof(Request) - (sizeof(auth) + sizeof(body))};

            std::shared_ptr<Request> p_request(new Request);

            // Copy all other than auth & body
            memcpy(p_request.get(), request, static_request_size);

            return std::move(p_request);
        }

        void SetAuth(std::string auth_str)
        {
            if (auth != nullptr)
                return;

            auth_size = auth_str.size();
            auth = std::make_unique<std::uint8_t *>(new std::uint8_t[auth_size]);

            memcpy(auth.get(), auth_str.data(), auth_size);
        }

        void SetBody(std::string body_str)
        {
            if (body != nullptr)
                return;

            body_size = body_str.size();
            body = std::make_unique<std::uint8_t *>(new std::uint8_t[body_size]);

            memcpy(body.get(), body_str.data(), body_size);
        }
    };

    class Socket
    {
    public:
        Socket() {}

        Socket(const char *ip, uint16_t port)
        {
            Init(ip, port);
        }

        ~Socket()
        {
#ifdef _WIN32
            WSACleanup();
#endif
        }

        bool Init(const char *ip, uint16_t port)
        {
            if (is_init)
                return false;

#ifdef _WIN32
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
                return true;
#endif

            if ((file_descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
            {
                return true;
                // throw std::runtime_error("[NET SOCKET] Failed to create socket");
            }

            address.sin_family = AF_INET;

            if (int result = inet_pton(AF_INET, ip, &address.sin_addr) <= 0)
            {
                if (result == 0)
                {
                    return true;
                    // throw std::runtime_error("[NET SOCKET] SRC does not have valid address family");
                }
                else
                {
                    return true;
                    // throw std::runtime_error("[NET SOCKET] AF does not have valid address family");
                }
            }

            address.sin_port = htons(port);

            is_init = true;

            return false;
        }

        bool IsInit()
        {
            return is_init;
        }

    protected:
        bool is_init{};
        int file_descriptor;
        sockaddr_in address;

#ifdef _WIN32
        WSADATA wsaData;
#endif
    };

    class CSocket : public Socket
    {
    public:
        using Socket::Socket;

        void Connect()
        {
            if (connect(file_descriptor, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == -1)
                throw std::runtime_error("[NET CSOCKET] Failed to connect with socket");
        }

        void Send(Request &request)
        {
            static size_t static_request_size{sizeof(Request) - (sizeof(Request::auth) + sizeof(Request::body))};
            send(file_descriptor, reinterpret_cast<char*>(request.ToRaw().get()), static_request_size + request.auth_size + request.body_size, 0);
        }
    };

    class SSocket : public Socket
    {
    public:
        using Socket::Socket;

        void Bind()
        {

#ifdef _WIN32 // fuck windows seriously wtf
            char opt{ 1 };
            setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#else 
            int opt{1};
            setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
#endif

            if (bind(file_descriptor, (struct sockaddr *)&address, sizeof(address)) == -1)
                throw std::runtime_error("[NET SSOCKET] Failed to bind socket");
        }

        void Accept()
        {
            static int addrlen{sizeof(address)};

            if (listen(file_descriptor, 1000) < 0)
                throw std::runtime_error("[NET SSOCKET] Failed to listen");

            while (int socket = accept(file_descriptor, (sockaddr *)&address,
                                       (socklen_t *)&addrlen))
            {
                char magic[3];

#ifdef _WIN32 // fuck windows seriously wtf
                ssize_t count{read(socket, magic, 3, 0)};
#else 
                ssize_t count{ read(socket, magic, 3) };
#endif

                if (strncmp(magic, "NET", 3) == 0)
                {
                    static const size_t static_request_size{sizeof(Request) - (sizeof(Request::auth) + sizeof(Request::body))};

                    std::uint8_t raw_request[static_request_size];
                    memcpy(raw_request, "NET", 3);

#ifdef _WIN32 // fuck windows seriously wtf
                    count = read(socket, reinterpret_cast<char*>(raw_request) + 3, static_request_size - 3, 0);
#else 
                    count = read(socket, reinterpret_cast<char*>(raw_request) + 3, static_request_size - 3);
#endif

                    auto p_request{Request::Parse(raw_request)};

                    /* Fetch auth if exists */
                    if (p_request->auth_size != 0)
                    {
                        p_request->auth = std::make_unique<std::uint8_t *>(new std::uint8_t[p_request->auth_size]);
#ifdef _WIN32 // fuck windows seriously wtf
                        count = read(socket, reinterpret_cast<char*>(p_request->auth.get()), p_request->auth_size, 0);
#else 
                        count = read(socket, reinterpret_cast<char*>(p_request->auth.get()), p_request->auth_size);
#endif
                    }

                    /* Fetch body if exists */
                    if (p_request->body_size != 0)
                    {
                        p_request->body = std::make_unique<std::uint8_t *>(new std::uint8_t[p_request->body_size]);
#ifdef _WIN32 // fuck windows seriously wtf
                        count = read(socket, reinterpret_cast<char*>(p_request->body.get()), p_request->body_size, 0);
#else 
                        count = read(socket, reinterpret_cast<char*>(p_request->body.get()), p_request->body_size);
#endif
                    }

                    Handler(p_request);
                }
                else
                    send(socket, "INVALID", 8, 0);
            }
        }

        void Handler(std::shared_ptr<NET::Request> &p_request)
        {
            printf("Received request\n");
        }
    };
}

#endif
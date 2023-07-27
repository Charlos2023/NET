#ifndef NET_PARAMOUNT_H_
#define NET_PARAMOUNT_H_

#include <memory>
#include <string>
#include <stdexcept>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace NET
{
    static char c_zero{'\0'};

    enum STATUS
    {
        OK = 0,
        NOT_FOUND,
        UNAUTHORIZED,
        INTERNAL_ERROR,
        MALFORMED,
    };

    enum METHOD
    {
        GET = 0,
        POST,
        UPDATE,
        DELETE
    };

    struct Request;
    static size_t REQUEST_STATIC_SIZE{sizeof(Request) - (sizeof(Request::auth) + sizeof(Request::body))};

    struct Request
    {
        char magic[3]{'N', 'E', 'T'};
        uint8_t method;
        char path[256];
        size_t body_size;
        size_t auth_size;
        std::unique_ptr<std::uint8_t> auth;
        std::unique_ptr<std::uint8_t> body;

        ~Request()
        {
            auth.release();
            body.release();
        }

        std::shared_ptr<uint8_t> ToRaw()
        {
            std::shared_ptr<uint8_t> raw(new std::uint8_t[REQUEST_STATIC_SIZE + auth_size + body_size]);

            memcpy(raw.get(), this, REQUEST_STATIC_SIZE);

            /* If no token set it to '\0' */
            if (auth == nullptr)
            {
                // dumb and to change since you don't need to alloc a whole block for a single byte
                auth = std::make_unique<std::uint8_t>(new std::uint8_t[1]);
                *auth.get() = '\0';
            }

            memcpy(raw.get() + REQUEST_STATIC_SIZE, this->auth.get(), auth_size);

            /* If no body set it to '\0' */
            if (body == nullptr)
            {
                // dumb and to change since you don't need to alloc a whole block for a single byte
                body = std::make_unique<std::uint8_t>(new std::uint8_t[1]);
                *body.get() = '\0';
            }

            memcpy(raw.get() + REQUEST_STATIC_SIZE + auth_size, this->body.get(), body_size);

            return std::move(raw);
        }

        static std::shared_ptr<Request> Parse(std::uint8_t *raw_request)
        {
            std::shared_ptr<Request> parsed_request(new Request);

            static size_t static_size{REQUEST_STATIC_SIZE - sizeof(Request::magic)};
            memcpy(parsed_request.get() + sizeof(Request::magic), raw_request, static_size);

            parsed_request->auth = std::make_unique<std::uint8_t>(new std::uint8_t[parsed_request->auth_size]);
            memcpy(parsed_request->auth.get(), raw_request + static_size, parsed_request->auth_size);

            parsed_request->body = std::make_unique<std::uint8_t>(new std::uint8_t[parsed_request->body_size]);
            memcpy(parsed_request->body.get(), raw_request + static_size + parsed_request->auth_size, parsed_request->body_size);

            return std::move(parsed_request);
        }
    };

    struct Response;
    static size_t RESPONSE_STATIC_SIZE{sizeof(Response) - sizeof(Response::body)}; // wtf C++

    struct Response
    {
        uint8_t status;
        size_t body_size;
        std::unique_ptr<std::uint8_t> body;

        std::shared_ptr<std::uint8_t> ToRaw()
        {
            std::shared_ptr<std::uint8_t> raw_data(new std::uint8_t[RESPONSE_STATIC_SIZE + body_size]);

            memcpy(raw_data.get(), this, RESPONSE_STATIC_SIZE);

            if (body_size != 0)
                memcpy(raw_data.get() + RESPONSE_STATIC_SIZE, body.get(), body_size);

            return std::move(raw_data);
        }
    };

    class Socket
    {
    public:
        Socket(const char *ip, uint16_t port)
        {
            if (file_descriptor = socket(AF_INET, SOCK_STREAM, 0) == -1)
                throw std::runtime_error("[NET SOCKET] Failed to create socket");

            address.sin_family = AF_INET;

            if (int result = inet_pton(AF_INET, ip, &address.sin_addr) <= 0)
            {
                if (result == 0)
                    throw std::runtime_error("[NET SOCKET] SRC does not have valid address family");
                else
                    throw std::runtime_error("[NET SOCKET] AF does not have valid address family");
            }

            address.sin_port = htons(port);
        }

    protected:
        sockaddr_in address;
        int file_descriptor;
    };

    class CSocket : public Socket
    {
    public:
        void Connect()
        {
            if (connect(file_descriptor, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == -1)
                throw std::runtime_error("[NET CSOCKET] Failed to connect with socket");
        }
    };

    class SSocket : public Socket
    {
    public:
        typedef void (*TRequestCallback)(int, Request &); // int socket, Request request

        void Bind()
        {
            if (bind(file_descriptor, (struct sockaddr *)&address, sizeof(address)) == -1)
                throw std::runtime_error("[NET SSOCKET] Failed to bind socket");
        }

        void Accept()
        {
            int addrlen = sizeof(address);

            while (int socket = accept(file_descriptor, (sockaddr *)&address,
                                       (socklen_t *)&addrlen))
            {
                char magic[3];
                ssize_t count{read(socket, magic, 3)};

                if (strncmp(magic, "NET", 3))
                {
                    uint8_t static_request[REQUEST_STATIC_SIZE - sizeof(Request::magic)];
                    count = read(socket, static_request, sizeof(static_request));

                    std::shared_ptr<Request> p_request{Request::Parse(static_request)};

                    printf("%i\n", p_request->body_size);
                }
                else
                {
                    Response res{STATUS::MALFORMED, 0};
                    send(socket, &res, sizeof(res.status) + sizeof(res.body_size), 0);
                }
            }
        }
    };
}

#endif
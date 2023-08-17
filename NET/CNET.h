#ifndef NET_CNET_H_
#define NET_CNET_H_

#include "Paramout.h"

namespace NET
{
    class CNET
    {
    public:
        CNET() {}

        CNET(const char *ip, uint16_t port)
        {
            Init(ip, port);
        }

        CNET(const CNET &) = delete;

        bool Init(const char *ip, uint16_t port)
        {
            if (is_init)
                return false;

            if (socket.Init(ip, port))
            {
                return true;
                // throw std::runtime_error("[CNET] Failed to init socket\n");
            }

            socket.Connect();

            is_init = true;

            return false;
        }

        bool IsInit()
        {
            return is_init;
        }

        void GET(const char path[256])
        {
            NET::Request request;
            request.method = static_cast<std::uint8_t>(METHOD::GET);
            std::memcpy(&request.path, path, 256);

            socket.Send(request);
        }

        void POST(const char path[256], std::string body)
        {
            NET::Request request;
            request.method = static_cast<std::uint8_t>(METHOD::GET);
            std::memcpy(&request.path, path, 256);
            request.SetBody(body);

            socket.Send(request);
        }

    private:
        bool is_init{};
        CSocket socket{};
    };
}

#endif
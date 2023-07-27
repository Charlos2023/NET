#ifndef NET_CNET_H_
#define NET_CNET_H_

#include <string_view>
#include <memory>

#include "Paramount.h"

namespace NET
{
    class CNET
    {
    public:
        CNET(std::string_view ip, uint16_t port)
        {
            socket = std::make_unique<CSocket>(ip, port);
        }

        //
        // Network Methods
        //

        void GET(const char *path)
        {
        }

        void POST(const char *path, std::string body)
        {
        }

        void DELETE(const char *path)
        {
        }

        void UPDATE(const char *path, std::string body)
        {
        }

    private:
        std::unique_ptr<CSocket> socket;
        std::string_view ip;
    };
}

#endif
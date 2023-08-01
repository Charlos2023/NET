#ifndef NET_SNET_H_
#define NET_SNET_H_

#include "Paramout.h"

namespace NET
{
    class SNET
    {
    public:
        SNET() {}

        SNET(const char *bind_ip, uint16_t bind_port)
        {
            Init(bind_ip, bind_port);
        }

        bool Init(const char *bind_ip, uint16_t bind_port)
        {
            if (is_init)
                return false;

            if (socket.Init(bind_ip, bind_port))
            {
                return true;
                // throw std::runtime_error("[SNET] Failed to init socket\n");
            }

            socket.Bind();

            is_init = true;

            return false;
        }

        bool IsInit()
        {
            return is_init;
        }

        void Listen()
        {
            socket.Accept();
        }

    private:
        bool is_init{};
        SSocket socket;
    };
}

#endif
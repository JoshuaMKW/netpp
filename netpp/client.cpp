#include "netpp/client.h"

#define CLIENT_ERROR_REASON_CAPACITY 32

namespace netpp {

static const char* s_client_errors[(int)EClientError::E_COUNT][CLIENT_ERROR_REASON_CAPACITY] = {
#ifdef _WIN32
    { "Failed to start up WSA subsystem",
        "Failed to retrieve port information",
        "Failed to allocate resources",
        "Failed to retrieve socket information",
        "Failed to bind socket",
        "Failed to listen on socket",
        "Failed to spin up server threads",
        "Failed to send data to the connection",
        "Failed to resolve address",
        "Failed to accept the incoming connection",
        "Failed to connect to the destination socket",
        "Failed to receive data from the connection",
        "Failed to send data to the connection",
        "Failed to receive data from the connection",
        "Socket was corrupted",
        "Failed to identify the protocol of the incoming data",
        "Failed to process the incoming data according to protocol",
    },
#else
    {
        "Failed to start up subsystem",
        "Failed to retrieve port information",
        "Failed to allocate resources",
        "Failed to retrieve socket information",
        "Failed to bind socket",
        "Failed to listen on socket",
        "Failed to spin up server threads",
        "Failed to send data to the connection",
        "Failed to resolve address",
        "Failed to accept the incoming connection",
        "Failed to connect to the destination socket",
        "Failed to receive data from the connection",
        "Failed to send data to the connection",
        "Failed to receive data from the connection",
        "Socket was corrupted",
        "Failed to identify the protocol of the incoming data",
        "Failed to process the incoming data according to protocol",
    },
#endif
};

const char* client_error(EClientError error, int reason)
{
    if (reason >= CLIENT_ERROR_REASON_CAPACITY) {
        return "INVALID_REASON";
    }
    return s_client_errors[(int)error][reason];
}

} // namespace netpp

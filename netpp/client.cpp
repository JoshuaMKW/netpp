#include "netpp/client.h"

namespace netpp {

  static const char* s_client_errors[(int)EClientError::E_COUNT][16] = {
  #ifdef _WIN32
    {
      "Failed to start up WSA subsystem",
      "Failed to retrieve port information",
      "Failed to allocate resources",
      "Failed to retrieve socket information",
      "Failed to bind socket",
      "Failed to listen on socket",
      "Failed to spin up server threads",
      "Failed to send message",
      "Failed to resolve address",
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
      "Failed to send message",
      "Failed to resolve address",
    },
  #endif
  };

  const char* client_error(EClientError error, int reason) {
    return s_client_errors[(int)error][reason];
  }

} // namespace netpp

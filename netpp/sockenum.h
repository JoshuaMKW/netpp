#pragma once

#include "netpp/netpp.h"

namespace netpp {

  enum class ESocketErrorReason {
    E_NONE = -1,
    E_REASON_STARTUP,
    E_REASON_PORT,
    E_REASON_RESOURCES,
    E_REASON_SOCKET,
    E_REASON_BIND,
    E_REASON_LISTEN,
    E_REASON_THREADS,
    E_REASON_SEND,
    E_REASON_ADDRESS,
    E_REASON_ACCEPT,
    E_REASON_CONNECT,
    E_REASON_RECV,
    E_REASON_SENDTO,
    E_REASON_RECVFROM,
    E_REASON_CORRUPT,
    E_REASON_ADAPTER_UNKNOWN,
    E_REASON_ADAPTER_FAIL,
    E_COUNT,
  };

  enum class EPipeOperation {
    E_NONE,  // Can be used to check for connectivity status using pipe->is_ready
    E_RECV,
    E_SEND,
    E_RECV_SEND,
    E_CLOSE,
  };

  enum class ESocketHint {
    E_NONE,
    E_SERVER,
    E_CLIENT,
  };

  enum class EIOState {
    E_NONE,
    E_ERROR,
    E_BUSY,
    E_ASYNC,
    E_PARTIAL,
    E_COMPLETE,
  };

  enum class ESendFlags {
    E_NONE = 0,
    E_FORCE_INSECURE = (1 << 30),
    E_PARTIAL_IO = (1 << 31),
  };
  NETPP_BITWISE_ENUM(ESendFlags)

}
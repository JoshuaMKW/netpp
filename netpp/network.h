#pragma once

#include <cstdint>

namespace netpp {

  struct RawPacket {
    const char* m_message;
    uint32_t m_length;
  };

  enum class EServiceType {
    E_BEST_EFFORT = 0,
    E_CONTROLLED_LOAD = 1,
    E_GUARANTEED = 2,
  };

  struct NetworkFlowSpec {
    int m_token_rate;                // bytes per second
    int m_token_bucket_size;         // short term burst size
    int m_peak_bandwidth;            // peak bytes per second
    int m_max_latency;               // microseconds
    int m_jitter_tolerance;          // microseconds
    EServiceType m_service_type;     // 0 = best effort, 1 = controlled load, 2 = guaranteed
    int m_max_sdu_size;              // maximum service data unit size
    int m_min_policed_size;          // minimum policed size
  };

  const char* network_ipv4();
  const char* network_ipv6();

}  // namespace netpp
#pragma once

struct RawPacket {
  const char* m_message;
  int m_length;
};

const char* network_ipv4();
const char* network_ipv6();

bool network_initialize();
void network_deinitialize();

// OS-specific network interface
void* network_interface();
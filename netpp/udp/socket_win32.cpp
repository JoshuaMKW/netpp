#include <chrono>
#include <iostream>
#include <thread>

#include "network.h"
#include "socket.h"

#include "server.h"

using namespace std::chrono;
using namespace std::chrono_literals;

#ifdef _WIN32

namespace netpp {

  UDP_Socket::UDP_Socket(ISocketOSSupportLayer* owner_socket_layer,
    StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ESocketHint hint)
    : m_hint(hint), m_recv_buf_block(StaticBlockAllocator::INVALID_BLOCK),
      m_send_buf_block(StaticBlockAllocator::INVALID_BLOCK) {
    m_socket_layer = SocketOSSupportLayerFactory::create(
      owner_socket_layer,
      recv_allocator, send_allocator,
      ETransportLayerProtocol::E_UDP, hint
    );
  }

  bool UDP_Socket::open(const char* hostname, const char* port) {
    return m_socket_layer->open(hostname, port);
  }

  void UDP_Socket::close() {
    m_socket_layer->close();
  }

  bool UDP_Socket::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    return m_socket_layer->recv(offset, flags, transferred_out);
  }

  bool UDP_Socket::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    bool ret = send(request_buf, request_buf_size, nullptr);
    delete[] request_buf;
    return ret;
  }

  bool UDP_Socket::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    bool ret = send(request_buf, request_buf_size, nullptr);
    delete[] request_buf;
    return ret;
  }

  bool UDP_Socket::send(const RawPacket* packet) {
    const char* packet_buf = RawPacket::build_buf(*packet);
    bool ret = send(packet_buf, packet->length() + 4, nullptr);
    delete[] packet_buf;
    return ret;
  }

  void UDP_Socket::clone_callbacks_from(ISocketPipe* other) {
    UDP_Socket* udp = static_cast<UDP_Socket*>(other);
    m_socket_layer->clone_callbacks_from(udp->m_socket_layer);
    m_signal_dns_request = udp->m_signal_dns_request;
    m_signal_dns_response = udp->m_signal_dns_response;
    m_signal_http_request = udp->m_signal_http_request;
    m_signal_http_response = udp->m_signal_http_response;
    m_signal_raw_receive = udp->m_signal_raw_receive;
    m_signal_rtp_packet = udp->m_signal_rtp_packet;
    m_signal_sip_request = udp->m_signal_sip_request;
    m_signal_sip_response = udp->m_signal_sip_response;
  }

}  // namespace netpp

#endif
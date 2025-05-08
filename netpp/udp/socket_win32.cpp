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

  EIOState UDP_Socket::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    int32_t ret = m_socket_layer->recv(offset, flags, transferred_out);

    if (ret == -1) {
      // The socket or input is corrupted
      return EIOState::E_ERROR;
    } else if (ret == 0) {
      // The socket is busy, call again
      // after the transaction confirms
      return EIOState::E_BUSY;
    } else {
      m_io_info.m_last_op = EPipeOperation::E_RECV;
      m_io_info.m_recv_state.m_bytes_buf = m_socket_layer->recv_buf();
      m_io_info.m_recv_state.m_bytes_total = 0;
      m_io_info.m_recv_state.m_bytes_transferred = 0;

      // The socket sent all the data
      return EIOState::E_ASYNC;
    }
  }

  EIOState UDP_Socket::send(const char* data, uint32_t size, uint32_t* flags) {
    int32_t transferred = m_socket_layer->send(data, size, flags);
    

    if (transferred == -1) {
      // The socket or input is corrupted
      return EIOState::E_ERROR;
    } else if (transferred == 0) {
      // The socket is busy, call again
      // after the transaction confirms
      return EIOState::E_BUSY;
    } else if (transferred < size) {
      m_io_info.m_last_op = EPipeOperation::E_SEND;
      m_io_info.m_send_state.m_bytes_buf = data;
      m_io_info.m_send_state.m_bytes_total = size;
      m_io_info.m_send_state.m_bytes_transferred = transferred;

      // The socket fragmented the data
      // and we need to send the rest
      return EIOState::E_PARTIAL;
    } else {
      m_io_info.m_last_op = EPipeOperation::E_SEND;
      m_io_info.m_send_state.m_bytes_buf = data;
      m_io_info.m_send_state.m_bytes_total = size;
      m_io_info.m_send_state.m_bytes_transferred = transferred;

      // The socket sent all the data
      return EIOState::E_COMPLETE;
    }
  }

  EIOState UDP_Socket::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState UDP_Socket::send(const HTTP_Response* response) {
    uint32_t response_buf_size = 0;
    const char* response_buf = HTTP_Response::build_buf(*response, &response_buf_size);
    return send(response_buf, response_buf_size, nullptr);
  }

  EIOState UDP_Socket::send(const RawPacket* packet) {
    const char* packet_buf = RawPacket::build_buf(*packet);
    return send(packet_buf, packet->length() + 4, nullptr);
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
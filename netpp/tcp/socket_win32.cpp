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

  TCP_Socket::TCP_Socket(ISocketPipe* root_socket,
    StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ESocketHint hint)
    : m_hint(hint), m_recv_buf_block(StaticBlockAllocator::INVALID_BLOCK), m_send_buf_block(StaticBlockAllocator::INVALID_BLOCK) {
    ISocketOSSupportLayer* layer = nullptr;
    if (root_socket) {
      layer = root_socket->get_os_layer();
    }
    m_socket_layer = SocketOSSupportLayerFactory::create(
      layer,
      recv_allocator, send_allocator,
      ETransportLayerProtocol::E_TCP, hint, this
    );
  }

  bool TCP_Socket::open(const char* hostname, const char* port) {
    m_host_name = hostname;
    m_port = port;
    return m_socket_layer->open(hostname, port);
  }

  bool TCP_Socket::open(uint64_t socket_) {
    int namelen = sizeof(sockaddr_in);
    sockaddr_in addr;

    int rc = getpeername(socket_, (sockaddr*)&addr, &namelen);
    if (rc == SOCKET_ERROR) {
      return false;
    }

    m_host_name.resize(INET_ADDRSTRLEN + 1);
    inet_ntop(AF_INET, &addr.sin_addr, (char*)m_host_name.data(), INET_ADDRSTRLEN);

    m_port = std::to_string(ntohs(addr.sin_port));

    return m_socket_layer->open(socket_);
  }

  void TCP_Socket::close() {
    m_socket_layer->close();
    m_host_name = "";
    m_port = "";
  }

  EIOState TCP_Socket::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    SocketIOState& io_state = m_io_info.m_recv_state;

    //if (io_state.m_state == EIOState::E_ASYNC) {
    //  // The socket is busy, call again
    //  // after the transaction confirms
    //  return EIOState::E_BUSY;
    //}

    int32_t ret = m_socket_layer->recv(offset, flags, transferred_out);
    EIOState state = m_socket_layer->state(EPipeOperation::E_RECV);

    switch (state) {
    case EIOState::E_BUSY:
      // The socket is busy, call again
      // after the transaction confirms
      break;
    case EIOState::E_ASYNC:
      // The socket sent all the data
      io_state.m_bytes_buf = m_socket_layer->recv_buf();
      io_state.m_bytes_total = -1;
      io_state.m_bytes_transferred = 0;
      break;
    case EIOState::E_COMPLETE:
      io_state.m_bytes_buf = m_socket_layer->recv_buf();
      io_state.m_bytes_total = -1;
      io_state.m_bytes_transferred = 0;
      break;
    case EIOState::E_ERROR:
      // The socket or input is corrupted
      break;
    }

    return state;
  }

  EIOState TCP_Socket::send(const char* data, uint32_t size, uint32_t* flags) {
    if (!data || size == 0) {
      return EIOState::E_ERROR;
    }

    SocketIOState& io_state = m_io_info.m_send_state;

    EIOState last_state = m_socket_layer->state(EPipeOperation::E_SEND);

    if (last_state == EIOState::E_PARTIAL) {
      if (!flags || (*flags & IO_FLAG_PARTIAL) == 0) {
        // The socket is busy, call again
        // after the transaction confirms
        return EIOState::E_BUSY;
      }

      int32_t transferred = m_socket_layer->send(data, size, flags);
      EIOState state = m_socket_layer->state(EPipeOperation::E_SEND);

      switch (state) {
      case EIOState::E_BUSY:
        // The socket is busy, call again
        // after the transaction confirms
        break;
      case EIOState::E_ASYNC:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        io_state.m_bytes_buf = data;
        io_state.m_bytes_total = -1;
        io_state.m_bytes_transferred = 0;
        break;
      case EIOState::E_COMPLETE:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        io_state.m_bytes_buf = data;
        io_state.m_bytes_total = size;
        io_state.m_bytes_transferred = transferred;
        break;
      case EIOState::E_PARTIAL:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        io_state.m_bytes_buf = data;
        io_state.m_bytes_total = size;
        io_state.m_bytes_transferred = transferred;
        break;
      case EIOState::E_ERROR:
        // The socket or input is corrupted
        break;
      }
    }

    int32_t transferred = m_socket_layer->send(data, size, flags);
    EIOState state = m_socket_layer->state(EPipeOperation::E_SEND);

    switch (state) {
    case EIOState::E_BUSY:
      // The socket is busy, call again
      // after the transaction confirms
      break;
    case EIOState::E_ASYNC:
      m_io_info.m_last_op = EPipeOperation::E_SEND;
      io_state.m_bytes_buf = data;
      io_state.m_bytes_total = size;
      io_state.m_bytes_transferred = transferred;
      break;
    case EIOState::E_COMPLETE:
      m_io_info.m_last_op = EPipeOperation::E_SEND;
      io_state.m_bytes_buf = data;
      io_state.m_bytes_total = size;
      io_state.m_bytes_transferred = transferred;
      break;
    case EIOState::E_PARTIAL:
      m_io_info.m_last_op = EPipeOperation::E_SEND;
      io_state.m_bytes_buf = data;
      io_state.m_bytes_total = size;
      io_state.m_bytes_transferred = transferred;
      break;
    case EIOState::E_ERROR:
      // The socket or input is corrupted
      break;
    }

    return state;
  }

  EIOState TCP_Socket::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState TCP_Socket::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState TCP_Socket::send(const RawPacket* packet) {
    const char* packet_buf = RawPacket::build_buf(*packet);
    return send(packet_buf, packet->length() + 4, nullptr);
  }

  void TCP_Socket::clone_callbacks_from(ISocketPipe* other) {
    TCP_Socket* tcp = static_cast<TCP_Socket*>(other);
    m_socket_layer->clone_callbacks_from(tcp->m_socket_layer);
    m_signal_dns_request = tcp->m_signal_dns_request;
    m_signal_dns_response = tcp->m_signal_dns_response;
    m_signal_http_request = tcp->m_signal_http_request;
    m_signal_http_response = tcp->m_signal_http_response;
    m_signal_raw_receive = tcp->m_signal_raw_receive;
    m_signal_rtp_packet = tcp->m_signal_rtp_packet;
    m_signal_sip_request = tcp->m_signal_sip_request;
    m_signal_sip_response = tcp->m_signal_sip_response;
  }

}  // namespace netpp

#endif
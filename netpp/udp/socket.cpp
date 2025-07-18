#include <chrono>
#include <iostream>
#include <thread>

#include "network.h"
#include "socket.h"

#include "server.h"

using namespace std::chrono;
using namespace std::chrono_literals;

namespace netpp {

  UDP_Socket::UDP_Socket(ISocketPipe* root_socket,
    StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ESocketHint hint)
    : m_hint(hint), m_recv_buf_block(StaticBlockAllocator::INVALID_BLOCK), m_send_buf_block(StaticBlockAllocator::INVALID_BLOCK) {
    ISocketOSSupportLayer* layer = nullptr;
    if (root_socket) {
      layer = root_socket->get_os_layer();
    }
    m_socket_layer = SocketOSSupportLayerFactory::create(
      layer,
      recv_allocator, send_allocator,
      ETransportLayerProtocol::E_UDP, hint, this
    );
  }

  bool UDP_Socket::open(const char* hostname, const char* port) {
    m_host_name = hostname;
    m_port = port;

    if (!m_socket_layer->open(hostname, port)) {
      return false;
    }

    if (m_security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
        m_socket_layer->close();
        return false;
      }
      return m_security->initialize();
    }

    return true;
  }

  bool UDP_Socket::open(uint64_t socket_) {
    int namelen = sizeof(sockaddr_in);
    sockaddr_in addr;

    int rc = getpeername(socket_, (sockaddr*)&addr, &namelen);
    if (rc == SOCKET_ERROR) {
      return false;
    }

    m_host_name.resize(INET_ADDRSTRLEN + 1);
    inet_ntop(AF_INET, &addr.sin_addr, (char*)m_host_name.data(), INET_ADDRSTRLEN);

    m_port = std::to_string(ntohs(addr.sin_port));

    if (!m_socket_layer->open(socket_)) {
      return false;
    }

    if (m_security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
        m_socket_layer->close();
        return false;
      }
      return m_security->initialize();
    }

    return true;
  }

  void UDP_Socket::close() {
    m_socket_layer->close();
    m_host_name = "";
    m_port = "";

    if (m_security) {
      m_security->deinitialize();
    }
  }

  bool UDP_Socket::accept(accept_cond_cb accept_cond, accept_cb accept_routine)
  {
    if (m_security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
        return false;
      }

      if (!m_security->set_accept_state()) {
        return false;
      }
    }

    return m_socket_layer->accept(accept_cond, accept_routine);
  }

  bool UDP_Socket::connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec)
  {
    if (m_security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
        return false;
      }

      if (!m_security->set_connect_state()) {
        return false;
      }
    }

    return m_socket_layer->connect(timeout, recv_flowspec, send_flowspec);
  }

  EIOState UDP_Socket::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    SocketIOState& io_state = m_io_info.m_recv_state;

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

  EIOState UDP_Socket::send(const char* data, uint32_t size, uint32_t* flags) {
    if (!data || size == 0) {
      return EIOState::E_ERROR;
    }

    const char* data_ptr = data;
    int64_t data_size = size;
    if (m_security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
        return EIOState::E_ERROR;
      }

      char* the_data;

      data_size = m_security->encrypt(data, size, &the_data);
      if (data_size == -1) {
        return EIOState::E_ERROR;
      }

      data_ptr = the_data;
    }

    SocketIOState& io_state = m_io_info.m_send_state;

    EIOState last_state = m_socket_layer->state(EPipeOperation::E_SEND);

    if (last_state == EIOState::E_PARTIAL) {
      if (!flags || (*flags & (uint32_t)ESendFlags::E_PARTIAL_IO) == 0) {
        // The socket is busy, call again
        // after the transaction confirms
        return EIOState::E_BUSY;
      }

      int32_t transferred = m_socket_layer->send(data_ptr, data_size, flags);
      EIOState state = m_socket_layer->state(EPipeOperation::E_SEND);

      switch (state) {
      case EIOState::E_BUSY:
        // The socket is busy, call again
        // after the transaction confirms
        break;
      case EIOState::E_ASYNC:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        io_state.m_bytes_total = -1;
        break;
      case EIOState::E_COMPLETE:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        delete[] io_state.m_bytes_buf;
        io_state.m_bytes_buf = nullptr;
        io_state.m_bytes_transferred += transferred;
        break;
      case EIOState::E_PARTIAL:
        m_io_info.m_last_op = EPipeOperation::E_SEND;
        io_state.m_bytes_transferred += transferred;
        break;
      case EIOState::E_ERROR:
        // The socket or input is corrupted
        break;
      }
    }

    int32_t transferred = m_socket_layer->send(data_ptr, data_size, flags);
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
      delete[] data;
      io_state.m_bytes_buf = nullptr;
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

  EIOState UDP_Socket::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState UDP_Socket::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState UDP_Socket::send(const RawPacket* packet) {
    const char* packet_buf = RawPacket::build_buf(*packet);
    return send(packet_buf, packet->length() + 4, nullptr);
  }

  void UDP_Socket::clone_callbacks_from(ISocketPipe* other) {
    UDP_Socket* tcp = static_cast<UDP_Socket*>(other);
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

  EAuthState UDP_Socket::proc_pending_auth(EPipeOperation last_op, int32_t post_transferred)
  {
    if (!m_security) {
      return EAuthState::E_NONE;
    }

    ETransportProtocolFlags transports = m_security->supported_transports();
    if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
      return EAuthState::E_FAILED;
    }

    return m_security->advance_handshake(this, last_op, post_transferred);
  }

  int32_t UDP_Socket::proc_post_recv(char** out_data, const char* in_data, uint32_t in_size)
  {
    if (!m_security) {
      *out_data = new char[in_size];
      memcpy_s(out_data, in_size, in_data, in_size);
      return in_size;
    }

    ETransportProtocolFlags transports = m_security->supported_transports();
    if ((transports & ETransportProtocolFlags::E_TCP) == ETransportProtocolFlags::E_NONE) {
      return -1;
    }

    return m_security->decrypt(in_data, in_size, out_data);
  }

}  // namespace netpp

#include "protocol.h"

#ifdef _WIN32

#define CLIENT_USE_WSA 0

#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>

static RIO_EXTENSION_FUNCTION_TABLE* s_rio;

namespace netpp {

  uint64_t TCPTransportAdapter::open_socket(EInternetLayerProtocol internet_protocol) {
    uint32_t family;
    switch (internet_protocol) {
    case EInternetLayerProtocol::E_IPV4:
    default:
      family = AF_INET;
      break;
    case EInternetLayerProtocol::E_IPV6:
      family = AF_INET6;
      break;
    }

#if CLIENT_USE_WSA
    return ::WSASocket(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    return ::socket(family, SOCK_STREAM, IPPROTO_TCP);
#endif
  }

  void TCPTransportAdapter::close_socket(uint64_t sockfd) {
    ::closesocket(sockfd);
  }

  bool TCPTransportAdapter::bind(uint64_t sockfd, sockaddr* inaddr) {
    return ::bind(sockfd, inaddr, sizeof(sockaddr)) == 0;
  }

  bool TCPTransportAdapter::listen(uint64_t sockfd, uint32_t backlog) {
    return ::listen(sockfd, backlog) == 0;
  }

  bool TCPTransportAdapter::connect(uint64_t sockfd, sockaddr* inaddr, const NetworkFlowSpec* recv_spec, const NetworkFlowSpec* send_spec) {
#if CLIENT_USE_WSA
    QOS qos;
    ZeroMemory(&qos, sizeof(qos));

    qos.SendingFlowspec.DelayVariation = send_spec->m_jitter_tolerance;
    qos.SendingFlowspec.ServiceType = (int)send_spec->m_service_type;
    qos.SendingFlowspec.TokenRate = send_spec->m_token_rate;
    qos.SendingFlowspec.TokenBucketSize = send_spec->m_token_bucket_size;
    qos.SendingFlowspec.PeakBandwidth = send_spec->m_peak_bandwidth;
    qos.SendingFlowspec.MaxSduSize = send_spec->m_max_sdu_size;
    qos.SendingFlowspec.MinimumPolicedSize = send_spec->m_min_policed_size;

    qos.ReceivingFlowspec.DelayVariation = recv_spec->m_jitter_tolerance;
    qos.ReceivingFlowspec.ServiceType = (int)recv_spec->m_service_type;
    qos.ReceivingFlowspec.TokenRate = recv_spec->m_token_rate;
    qos.ReceivingFlowspec.TokenBucketSize = recv_spec->m_token_bucket_size;
    qos.ReceivingFlowspec.PeakBandwidth = recv_spec->m_peak_bandwidth;
    qos.ReceivingFlowspec.MaxSduSize = recv_spec->m_max_sdu_size;
    qos.ReceivingFlowspec.MinimumPolicedSize = recv_spec->m_min_policed_size;

    // TODO: Potentially handle QOS differently here
    qos.ProviderSpecific.buf = (char*)&qos;
    qos.ProviderSpecific.len = sizeof(qos);

    return ::WSAConnect(sockfd, inaddr, sizeof(sockaddr), NULL, NULL, &qos, NULL) == 0;
#else
    return ::connect(sockfd, inaddr, sizeof(sockaddr)) == 0;
#endif
  }

  void TCPTransportAdapter::disconnect(uint64_t sockfd) {
    ::shutdown(sockfd, SD_BOTH);
  }

  bool TCPTransportAdapter::ping(uint64_t sockfd, sockaddr* inaddr) {
    char buf[1];
#if CLIENT_USE_WSA
    WSABUF wsa_buf = { 1, buf };
    DWORD flags = MSG_PEEK;
    DWORD recv_ = 0;
    return ::WSARecv(sockfd, &wsa_buf, 1, &recv_, &flags, NULL, NULL) > 0;
#else
    return ::recv(sockfd, buf, 1, MSG_PEEK) > 0;
#endif
  }

  bool TCPTransportAdapter::recv(uint64_t sockfd, sockaddr* inaddr, char* buffer, uint32_t size, uint32_t* flags, uint32_t* transferred_out) {
#if CLIENT_USE_WSA
    WSABUF buf = { size, buffer };
    DWORD transferred;
    DWORD flags_ = flags ? *flags : 0;
    BOOL rc = ::WSARecv(sockfd, &buf, 1, &transferred, &flags_, NULL, NULL);
    if (rc == SOCKET_ERROR) {
      int error = ::WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return false;
      }
    }

    if (flags) {
      *flags = flags_;
    }

    if (transferred_out) {
      *transferred_out = transferred;
    }

    return true;
#else
    uint32_t flags_ = flags ? *flags : 0;
    return ::recv(sockfd, buffer, size, flags_) > 0;
#endif
  }

  bool TCPTransportAdapter::send(uint64_t sockfd, sockaddr* inaddr, const char* data, uint32_t size, uint32_t* flags) {
#if CLIENT_USE_WSA
    Tag_WSA_BUF buf = { (char*)data, size, ESocketOperation::E_SEND, nullptr };
    Tag_WSA_OVERLAPPED overlapped = { &buf, ESocketOperation::E_SEND, nullptr };

    DWORD transferred;
    DWORD flags_ = flags ? *flags : 0;
    BOOL rc = ::WSASend(sockfd, &buf, 1, &transferred, flags_, &overlapped, NULL);
    if (rc == SOCKET_ERROR) {
      int error = ::WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return false;
      }
    }

    return true;
#else
    uint32_t flags_ = flags ? *flags : 0;
    return ::send(sockfd, data, size, flags_) > 0;
#endif
  }

}  // namespace netpp

#endif

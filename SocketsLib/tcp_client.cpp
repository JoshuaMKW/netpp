#include "client.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

TCP_Client::TCP_Client(int bufsize) {
  m_error = EClientError::E_NONE;
  m_reason = 0;

  m_socket_thread = 0;
  m_socket_pipe = { (int)INVALID_SOCKET, false, this };

  m_open_socket = INVALID_SOCKET;

  m_receive_callback = nullptr;
  m_response_callback = nullptr;

  if (bufsize > 0) {
    m_recvbuf = new char[bufsize];
    m_recvbuflen = bufsize;
  }
  else {
    m_recvbuf = new char[DEFAULT_BUFLEN];
    m_recvbuflen = DEFAULT_BUFLEN;
  }
}

TCP_Client::~TCP_Client() {
  if (is_running()) {
    stop();
  }

  if (m_recvbuf) {
    delete[] m_recvbuf;
    m_recvbuf = nullptr;
  }
}

bool TCP_Client::is_running() const {
  return m_open_socket != INVALID_SOCKET;
}

bool TCP_Client::start() {
  if (is_running()) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
    return false;
  }

#ifdef _WIN32
  return initialize_win32();
#else
  return initialize_unix();
#endif
}

void TCP_Client::stop() {
#ifdef _WIN32
  deinitialize_win32();
#else
  deinitialize_unix();
#endif
}

bool TCP_Client::connect(const char* hostname, const char* port) {
#ifdef _WIN32
  return connect_win32(hostname, port);
#else
  return connect_unix(hostname, port);
#endif
}

bool TCP_Client::send(HTTP_Request* request) {
  std::string request_str = http_request_str(request->method());
  request_str += " " + request->path() + " " + request->version() + "\r\n";

  const std::string* headers = request->headers();
  for (int i = 0; i < request->headers_count(); i++) {
    request_str += headers[i] + "\r\n";
  }

  if (request->has_body()) {
    std::string body = request->body();
    request_str += "Content-Length: " + std::to_string(body.length()) + "\r\n";
    request_str += "\r\n";
    request_str += body;
  }

  if (!send_message(m_open_socket, request_str.c_str(), request_str.length())) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return false;
  }

  return true;
}

bool TCP_Client::send(RawPacket* packet) {
  if (!send_message(m_open_socket, packet->m_message, packet->m_length)) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return false;
  }
  return true;
}

bool TCP_Client::initialize_win32() {
#ifndef _WIN32
  m_error = EServerError::E_ERROR_SOCKET;
  return false;
#endif
  m_open_socket = (int)::socket(AF_INET, SOCK_STREAM, 0);
  if (m_open_socket == INVALID_SOCKET) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
    return false;
  }

  return true;
}

void TCP_Client::deinitialize_win32() {
  if (m_open_socket != INVALID_SOCKET) {
    closesocket(m_open_socket);
    m_open_socket = INVALID_SOCKET;
  }

  WSACleanup();
}

bool TCP_Client::initialize_unix() {
  return false;
}

void TCP_Client::deinitialize_unix() {
}

bool TCP_Client::connect_win32(const char* hostname, const char* port) {
  int conn_result = 0;

  if (!is_running()) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
    return false;
  }

  // Close any existing connections
  if (m_socket_thread) {
    disconnect_win32();
  }

  sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(atoi(port));
  
  if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) != 1) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_ADDRESS;
    goto cleanup;
  }

  if (server_addr.sin_addr.s_addr == INADDR_NONE) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_PORT;
    goto cleanup;
  }

  if (::connect(m_open_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
    goto cleanup;
  }

  m_socket_pipe.m_socket = m_open_socket;

  m_socket_thread = (int)CreateThread(NULL, 0, client_thread_win32, &m_socket_pipe, 0, NULL);
  if (m_socket_thread == 0) {
    m_error = EClientError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_THREADS;
    goto cleanup;
  }

cleanup:
  if (m_error != EClientError::E_NONE) {
    disconnect_win32();
    return false;
  }

  m_host_name = hostname;
  m_host_port = port;

  return true;
}

void TCP_Client::disconnect_win32() {
  if (m_socket_thread) {
    m_socket_pipe.m_conn_alive = false;
    WaitForSingleObject((HANDLE)m_socket_thread, INFINITE);

    CloseHandle((HANDLE)m_socket_thread);
    m_socket_thread = 0;

    m_socket_pipe.m_socket = INVALID_SOCKET;
  }

  m_host_name = nullptr;
  m_host_port = nullptr;
}

unsigned long __stdcall TCP_Client::client_thread_win32(void* param)
{
  SocketPipe* pipe = (SocketPipe*)param;

  pipe->m_client->m_mutex.lock();
  pipe->m_conn_alive = true;
  pipe->m_client->m_mutex.unlock();

  char recvbuf[DEFAULT_BUFLEN];
  int recvbuflen = DEFAULT_BUFLEN;

  while (pipe->m_conn_alive) {
    int recv_result = recv(pipe->m_socket, recvbuf, recvbuflen, 0);
    if (recv_result == 0) {  // Connection closed
      pipe->m_conn_alive = false;
      continue;
    }
    else if (recv_result < 0) {  // Error
      pipe->m_conn_alive = false;
      continue;
    }

    pipe->m_client->m_mutex.lock();
    {
      bool response_handled = false;

      if (pipe->m_client->m_response_callback) {
        HTTP_Response* response = HTTP_Response::create(recvbuf, recv_result);
        if (response) {
          HTTP_Request* request = pipe->m_client->m_response_callback(pipe->m_client, response);
          if (request) {
            pipe->m_conn_alive = pipe->m_client->send(request);
            delete request;
          }
          response_handled = true;
          delete response;
        }
      }

      if (pipe->m_client->m_receive_callback && !response_handled) {
        RawPacket packet = { recvbuf, recv_result };
        RawPacket* response = pipe->m_client->m_receive_callback(pipe->m_client, &packet);
        if (response) {
          pipe->m_conn_alive = pipe->m_client->send(response);
          delete response;
        }
        response_handled = true;
      }

      // If the request was not handled
      if (!response_handled) {
        // Do nothing
      }
    }
    pipe->m_client->m_mutex.unlock();
  }

  return 0;
}

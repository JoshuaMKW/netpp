#pragma once

#include <mutex>

#include "network.h"
#include "response.h"
#include "request.h"
#include "socket.h"

enum class EClientError {
  E_NONE = -1,
  E_ERROR_SOCKET,
  E_COUNT,
};

const char* client_error(EClientError error, int reason);

class IClient {
public:
  typedef HTTP_Request* (*response_callback)(IClient* self, const HTTP_Response* request);
  typedef RawPacket* (*receive_callback)(IClient* self, const RawPacket* packet);

  virtual ~IClient() = default;

  virtual bool is_running() const = 0;

  virtual EClientError error() const = 0;
  virtual int reason() const = 0;

  virtual int socket() const = 0;
  virtual const char *host_name() const = 0;
  virtual const char *host_port() const = 0;

  // Set these before starting the server
  virtual void on_receive(receive_callback callback) = 0;
  virtual void on_response(response_callback callback) = 0;

  // Start the client on the specified port
  virtual bool start() = 0;
  virtual void stop() = 0;

  // Connect to the specified host port (server)
  virtual bool connect(const char* hostname, const char* port) = 0;

  // Blocking calls
  virtual bool send(HTTP_Request*) = 0;
  virtual bool send(RawPacket*) = 0;
};

class TCP_Client final : public IClient {
public:
  TCP_Client(int bufsize = -1);
  ~TCP_Client();

  bool is_running() const override;

  EClientError error() const override { return m_error; }
  int reason() const override { return m_reason; }

  int socket() const override { return m_open_socket; }
  const char *host_name() const override { return m_host_name; }
  const char *host_port() const override { return m_host_port; }

  // Set these before starting the server
  void on_receive(receive_callback callback) override { m_receive_callback = callback; }
  void on_response(response_callback callback) override { m_response_callback = callback; }

  bool start() override;
  void stop() override;

  bool connect(const char* hostname, const char* port) override;

  // Blocking calls
  bool send(HTTP_Request*) override;
  bool send(RawPacket*) override;

protected:
  friend struct SocketPipe;

  struct SocketPipe {
    int m_socket;
    bool m_conn_alive;
    TCP_Client* m_client;
    receive_callback m_callback;
  };

  bool initialize_win32();
  void deinitialize_win32();

  bool initialize_unix();
  void deinitialize_unix();

  bool connect_win32(const char* hostname, const char* port);
  bool connect_unix(const char* hostname, const char* port);

  void disconnect_win32();
  void disconnect_unix();

  static unsigned long __stdcall client_thread_win32(void* param);

private:
  EClientError m_error;
  int m_reason;

  int m_open_socket;
  const char* m_host_name;
  const char* m_host_port;

  int m_socket_thread;
  SocketPipe m_socket_pipe;

  char* m_recvbuf;
  int m_recvbuflen;

  response_callback m_response_callback;
  receive_callback m_receive_callback;

  std::mutex m_mutex;
};

class UDP_Client final : public IClient {
public:
  UDP_Client();
  ~UDP_Client();

  bool is_running() const override;

  // Set these before starting the server
  void on_receive(receive_callback callback) override { m_receive_callback = callback; }
  void on_response(response_callback callback) override { m_response_callback = callback; }

  bool start() override;
  void stop() override;

  // Blocking calls
  bool send(HTTP_Request*) override;
  bool send(RawPacket*) override;

protected:
  friend struct SocketPipe;

  struct SocketPipe {
    int m_socket;
    UDP_Client* m_server;
    receive_callback m_callback;
  };

  bool initialize_win32();
  void deinitialize_win32();

  bool initialize_unix();
  void deinitialize_unix();

  static unsigned long __stdcall server_thread_win32(void* param);

private:
  const char* m_port;

  EClientError m_error;
  int m_reason;

  int m_open_socket_count;
  SocketPipe* m_open_sockets;

  int* m_open_threads;

  char* m_recvbuf;
  int m_recvbuflen;

  response_callback m_response_callback;
  receive_callback m_receive_callback;

  std::mutex m_mutex;
};
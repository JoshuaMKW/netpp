#include "server.h"

#include <cassert>
#include <execution>
#include <thread>

#define DEFAULT_THREAD_MAX 4

#ifndef WANTS_EXPLICIT_AUTH_SYNC
#define WANTS_EXPLICIT_AUTH_SYNC false
#endif

namespace netpp {

  template <typename TV, typename TM>
  inline TV RoundDown(TV Value, TM Multiple) {
    return (Value / Multiple) * Multiple;
  }

  template <typename TV, typename TM>
  inline TV RoundUp(TV Value, TM Multiple) {
    return RoundDown(Value, Multiple) + (((Value % Multiple) > 0) ? Multiple : 0);
  }

  TCP_Server::TCP_Server(ISecurityFactory* security,
    uint32_t bufcount, uint32_t desired_bufsize, int max_threads)
    : m_stop_flag(false), m_security(security), m_server_socket(nullptr) {
    if (security) {
      ETransportProtocolFlags transports = m_security->supported_transports();
      assert((transports & ETransportProtocolFlags::E_TCP) != ETransportProtocolFlags::E_NONE
        && "Security controller must be TLS.");
    }

    m_error = EServerError::E_NONE;
    m_reason = -1;

    uint32_t granularity = 0;

#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    ::GetSystemInfo(&sysinfo);

    granularity = sysinfo.dwAllocationGranularity;
#else
    granularity = sysconf(_SC_PAGESIZE);
#endif

    if (desired_bufsize == 0) {
      desired_bufsize = granularity;
    }

    uint32_t desired_size = desired_bufsize * bufcount;
    desired_size = RoundUp(desired_size, granularity);

#ifdef _WIN32
    m_recvbuf = (char*)VirtualAlloc(NULL, desired_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    m_recvbuflen = desired_size;
    m_sendbuf = (char*)VirtualAlloc(NULL, desired_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    m_sendbuflen = desired_size;
#else
    m_recvbuf = new char[bufsize];
    m_recvbuflen = bufsize;
    m_sendbuf = new char[bufsize];
    m_sendbuflen = bufsize;
#endif

    m_recv_allocator.initialize(m_recvbuf, desired_bufsize, bufcount);
    m_send_allocator.initialize(m_sendbuf, desired_bufsize, bufcount);

    if (max_threads > 0) {
      m_max_threads = max_threads;
    }
    else {
#ifdef _WIN32
      m_max_threads = sysinfo.dwNumberOfProcessors * 2;
#else
      m_max_threads = sysconf(_SC_NPROCESSORS_ONLN) * 2;
#endif
    }

    if (m_max_threads == 0) {
      m_max_threads = DEFAULT_THREAD_MAX;
    }

    m_startup_thread = std::this_thread::get_id();

    ISecurityController* controller = nullptr;
    if (m_security) {
      controller = m_security->create_controller();
    }
    m_server_socket = new TCP_Socket(nullptr, &m_recv_allocator, &m_send_allocator, controller, ESocketHint::E_SERVER);
  }

  TCP_Server::~TCP_Server() {
    assert(is_startup_thread_cur() && "Server must be destroyed on the same thread it was created on.");
    if (is_running()) {
      stop();
    }

#ifdef _WIN32
    if (m_recvbuf) {
      VirtualFree(m_recvbuf, 0, MEM_RELEASE);
      m_recvbuf = nullptr;
    }

    if (m_sendbuf) {
      VirtualFree(m_sendbuf, 0, MEM_RELEASE);
      m_sendbuf = nullptr;
    }
#else 
    if (m_recvbuf) {
      delete[] m_recvbuf;
      m_recvbuf = nullptr;
    }

    if (m_sendbuf) {
      delete[] m_sendbuf;
      m_sendbuf = nullptr;
    }
#endif
  }

  bool TCP_Server::is_running() const {
    return m_process_thread.joinable() && !m_stop_flag;
  }

  bool TCP_Server::start(const char* hostname, const char* port) {
    if (is_running()) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
      return false;
    }

    return initialize(hostname, port);
  }

  void TCP_Server::stop() {
    assert(is_startup_thread_cur() && "Server must be stopped on the same thread it was created on.");
    {
      std::scoped_lock<std::recursive_mutex> lock(m_mutex);
      m_stop_flag = true;
    }
    deinitialize();
  }

  bool TCP_Server::send_all(const HTTP_Request* request) {
    bool result = true;
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&](auto& kv) {
      EIOState state = kv.second.m_pipe->send(request);
      if (state == EIOState::E_BUSY || state == EIOState::E_ERROR) {
        emit_error(kv.second.m_pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const HTTP_Response* response) {
    bool result = true;
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&](auto& kv) {
      EIOState state = kv.second.m_pipe->send(response);
      if (state == EIOState::E_BUSY || state == EIOState::E_ERROR) {
        emit_error(kv.second.m_pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const RawPacket* packet) {
    bool result = true;
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&](auto& kv) {
      EIOState state = kv.second.m_pipe->send(packet);
      if (state == EIOState::E_BUSY || state == EIOState::E_ERROR) {
        emit_error(kv.second.m_pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
        result = false;
      }
      });
    return result;
  }

  uint64_t TCP_Server::socket(const char* hostname, const char* port) {
    return 0;
  }

  bool TCP_Server::send(uint64_t socket, const HTTP_Request* request) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    EIOState state = pipe->send(request);

    if (state == EIOState::E_BUSY) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    if (state == EIOState::E_ERROR) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  bool TCP_Server::send(uint64_t socket, const HTTP_Response* response) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    EIOState state = pipe->send(response);

    if (state == EIOState::E_BUSY) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    if (state == EIOState::E_ERROR) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  bool TCP_Server::send(uint64_t socket, const RawPacket* packet) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    EIOState state = pipe->send(packet);

    if (state == EIOState::E_BUSY) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    if (state == EIOState::E_ERROR) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  void TCP_Server::emit_error(ISocketPipe* pipe, EServerError error, int reason) {
    m_error = error;
    m_reason = reason;

    const char* error_str = server_error(error, reason);

    if (pipe) {
      if (pipe == m_server_socket) {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (SERVER) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), error_str);
      }
      else {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (CLIENT: %llu) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), pipe->socket(), error_str);
      }
    }
    else {
      fprintf(stderr, "[SERVER] ERROR: Server (PROCESS) failed with reason: %s\n", error_str);
    }
  }

  bool TCP_Server::is_startup_thread_cur() const {
    return m_startup_thread == std::this_thread::get_id();
  }

  bool TCP_Server::initialize(const char* hostname, const char* port) {
    if (is_running()) {
      emit_error(nullptr, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return false;
    }

    m_server_socket->on_close([this](ISocketPipe* pipe) {
      m_purgatory_sockets.push(pipe->socket());
      return false;
      });

    m_server_socket->on_error([this](ISocketPipe* pipe, ESocketErrorReason reason) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)reason);
      return true;
      });

    if (!m_server_socket->open(hostname, port)) {
      deinitialize();
      return false;
    }

    if (!m_server_socket->bind()) {
      deinitialize();
      return false;
    }

    if (!m_server_socket->listen()) {
      deinitialize();
      return false;
    }

    m_accept_thread = std::thread(server_accept_thread, this);
    m_update_thread = std::thread(server_update_thread, this);
    m_process_thread = std::thread(server_process_thread, this);

    return true;
  }

  void TCP_Server::deinitialize() {
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);

    if (m_update_thread.joinable()) {
      m_update_thread.join();
    }

    if (m_accept_thread.joinable()) {
      m_accept_thread.join();
    }

    if (m_process_thread.joinable()) {
      m_process_thread.join();
    }

    m_server_socket->close();
    delete m_server_socket;

    m_server_socket = nullptr;

    for (auto& pipe : m_client_sockets) {
      delete pipe.second.m_pipe;
    }

    m_client_sockets.clear();

    SocketOSSupportLayerFactory::deinitialize();
  }

  ISocketPipe* TCP_Server::get_socket_pipe(uint64_t socket) {
    if (m_client_sockets.find(socket) == m_client_sockets.end()) {
      return nullptr;
    }
    return m_client_sockets[socket].m_pipe;
  }

  void TCP_Server::close_socket(ISocketPipe* pipe) {
    m_purgatory_sockets.push(pipe->socket());
  }

  IApplicationLayerAdapter* TCP_Server::handle_inproc_recv(SocketProcData& data, const ISocketIOResult::OperationData& info, bool& inproc) {
    IApplicationLayerAdapter* adapter = nullptr;
    ISocketPipe* pipe = data.m_pipe;

    const SocketIOInfo& sock_data = pipe->get_io_info();
    const char* recv_buf = pipe->get_os_layer()->recv_buf();

    // Update how many unprocessed bytes have been transferred...
    // ---

    //data.m_recv_state.m_bytes_transferred += info.m_bytes_transferred;

    // Under this circumstance, the total data hasn't been determined
    // yet, so allocate a temporary smaller one to process
    // the adapter with...
    // ---
    // We create a copy of the proc buffer pointer because
    // later we do some pointer swapping based on the
    // predicted size of the processed data...
    // ---
    char* proc_buf = nullptr;
    if (data.m_bytes_total == 0) {
      proc_buf = new char[info.m_bytes_transferred];
    }
    else {
      proc_buf = data.m_proc_buf;
    }

    // Here we process enough to determine the underlying protocol
    // ---
    // The goal is this--m_proc_buf points to the potentially decrypted
    // or otherwise post processed data taken from recv_buf.
    //
    // By keeping track of two buffers and the amount of bytes
    // processed, we are able to stitch together fragmented
    // data packets incoming from the socket...
    // ---
    char* post_out;
    int32_t true_size = pipe->proc_post_recv(
      &post_out,
      recv_buf,
      info.m_bytes_transferred
    );

    // It has failed in some manner...
    // ---
    if (true_size < 0) {
      delete[] proc_buf;
      inproc = false;
      return nullptr;
    }

    // Under this circumstance, the pipe is waiting
    // for more data to be received to complete the
    // processing. This is important for TLS Records
    // and other such structures...
    // ---
    if (true_size == 0) {
      delete[] proc_buf;
      inproc = true;
      return nullptr;
    }

    // Update the processed marker so the next pass is correctly offset...
    // ---
    memcpy_s(proc_buf + data.m_bytes_processed, true_size, post_out, true_size);
    data.m_bytes_processed += true_size;

    // Then we attempt to identify what kind of data is coming in from
    // the socket... this is done after decryption so we can identify
    // the application layer protocol regardless of security used...
    // ---
    adapter = ApplicationAdapterFactory::detect(proc_buf, true_size, m_security);
    if (!adapter) {
      delete adapter;
      delete[] proc_buf;
      inproc = false;
      return nullptr;
    }

    // Finally we calculate the expected capacity of the protocol data
    // ---
    if (data.m_bytes_total == 0) {
      data.m_bytes_total = adapter->calc_size(proc_buf, data.m_bytes_processed);
    }

    // If the adapter is not valid, we need to reset the state
    // and return an error...
    // ---
    if (data.m_bytes_total == 0) {
      pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
      delete adapter;
      delete[] proc_buf;

      data.m_bytes_total = 0;
      data.m_bytes_processed = 0;
      delete[] data.m_proc_buf;
      data.m_proc_buf = nullptr;
      return nullptr;
    }

    // Under the condition that the transferred data estimate doesn't
    // the total expected data, we go ahead and resize the
    // buffer to be the total bytes for the upcoming reads...
    // ---
    if (!data.m_proc_buf) {
      if (data.m_bytes_total > info.m_bytes_transferred) {
        char* new_proc_buf = new char[data.m_bytes_total];
        memcpy_s(
          new_proc_buf,
          data.m_bytes_processed,
          proc_buf,
          data.m_bytes_processed
        );
        delete[] proc_buf;
        data.m_proc_buf = new_proc_buf;
      }
      else {
        data.m_proc_buf = proc_buf;
      }
    }

    // Initiate the next read...
    if (data.m_bytes_processed < data.m_bytes_total) {
      delete adapter;
      uint32_t flags = 0;
      pipe->get_os_layer()->set_busy(EPipeOperation::E_RECV, false);
      uint32_t transferred;
      pipe->recv(0, &flags, &transferred);
      inproc = true;
      return nullptr;
    }

    inproc = false;
    return adapter;
  }

  bool TCP_Server::handle_auth_operations(SocketProcData& data, const ISocketIOResult::OperationData& info) {
    ISocketPipe* pipe = data.m_pipe;

    switch (info.m_operation) {
    case EPipeOperation::E_RECV: {
      //sock_data.m_recv_state.m_bytes_transferred = info.m_bytes_transferred;
      //sock_data.m_last_op = EPipeOperation::E_RECV;
      pipe->get_os_layer()->set_busy(EPipeOperation::E_RECV, false);
      break;
    }
    case EPipeOperation::E_SEND: {
      //sock_data.m_send_state.m_bytes_transferred = info.m_bytes_transferred;
      //sock_data.m_last_op = EPipeOperation::E_SEND;
      pipe->get_os_layer()->set_busy(EPipeOperation::E_SEND, false);
      return true;
    }
    case EPipeOperation::E_CLOSE: {
      pipe->close();
      return true;
    }
    default:
      return false;
    }

    EAuthState auth_state = pipe->proc_pending_auth(info.m_operation, info.m_bytes_transferred);
    if (auth_state == EAuthState::E_AUTHENTICATED) {
#if WANTS_EXPLICIT_AUTH_SYNC
      const char* data = "--AUTHENTICATED--";
      EIOState state = pipe->send(data, 18, nullptr);

      if (state == EIOState::E_BUSY) {
        pipe->error(ESocketErrorReason::E_REASON_SEND);
        m_pending_auth_sockets.erase(pipe->socket());
        return false;
      }

      if (state == EIOState::E_ERROR) {
        pipe->error(ESocketErrorReason::E_REASON_SEND);
        m_pending_auth_sockets.erase(pipe->socket());
        return false;
      }

      pipe->get_os_layer()->signal_io_complete(EPipeOperation::E_SEND);
#endif

      m_pending_auth_sockets.erase(pipe->socket());
      m_client_sockets[pipe->socket()] = SocketProcData(pipe);
    }
    else if (auth_state == EAuthState::E_FAILED) {
      m_pending_auth_sockets.erase(pipe->socket());

      pipe->close();
    }
    return true;
  }

  bool TCP_Server::handle_client_operations(SocketProcData& data, const ISocketIOResult::OperationData& info) {
    ISocketPipe* pipe = data.m_pipe;
    const SocketIOInfo& sock_data = pipe->get_io_info();

    switch (info.m_operation) {
    case EPipeOperation::E_RECV: {
      // Process the incoming and possibly incomplete
      // data packet.
      // ---
      bool inproc = false;
      IApplicationLayerAdapter* adapter = handle_inproc_recv(data, info, inproc);

      // Finalize the low-level state of the pipe.
      // ---
      ISocketOSSupportLayer* os_layer = pipe->get_os_layer();
      os_layer->set_transferred(EPipeOperation::E_RECV, sock_data.m_recv_state.m_bytes_transferred);
      os_layer->set_busy(EPipeOperation::E_RECV, false);

      if (inproc) {
        delete adapter;
        return true;
      }

      os_layer->signal_io_complete(EPipeOperation::E_RECV);

      // If the data is finished processing and the adapter
      // still hasn't been determined, send an error
      // and reset the server-owned socket state completely.
      // ---
      if (!adapter) {
        pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
        return false;
      }

      // Here we pass all of the aggregated processed data
      // handled by `handle_inproc_recv` to the adapter.
      // This is where the callbacks are signaled for
      // client code to handle.
      // ---
      uint32_t flags = 0;
      bool success = adapter->on_receive(
        pipe,
        data.m_proc_buf,
        data.m_bytes_processed,
        flags
      );

      // Reset the process buffer for the next
      // incoming data.
      // ---
      data.m_bytes_processed = 0;
      data.m_bytes_total = 0;
      delete[] data.m_proc_buf;
      data.m_proc_buf = nullptr;

      delete adapter;

      // The client code likely handled something incorrectly,
      // the adapter is not implemented yet, or the adapter
      // was incorrectly implemented.
      // ---
      if (!success) {
        pipe->error(ESocketErrorReason::E_REASON_ADAPTER_FAIL);
        return false;
      }

      return true;
    }
    case EPipeOperation::E_SEND: {
      ISocketOSSupportLayer* os_layer = pipe->get_os_layer();

      os_layer->set_transferred(EPipeOperation::E_SEND, sock_data.m_send_state.m_bytes_transferred);
      os_layer->set_busy(EPipeOperation::E_SEND, false);

      const int32_t bytes_left = sock_data.m_send_state.m_bytes_total - sock_data.m_send_state.m_bytes_transferred;
      if (bytes_left > 0) {
        uint32_t flags = (uint32_t)ESendFlags::E_PARTIAL_IO;

        // Send the remaining data
        EIOState state = pipe->send(
          sock_data.m_send_state.m_bytes_buf + sock_data.m_send_state.m_bytes_transferred,
          bytes_left,
          &flags
        );

        if (state == EIOState::E_BUSY) {
          pipe->error(ESocketErrorReason::E_REASON_SEND);
          m_pending_auth_sockets.erase(pipe->socket());
          return false;
        }

        if (state == EIOState::E_ERROR) {
          pipe->error(ESocketErrorReason::E_REASON_SEND);
          m_pending_auth_sockets.erase(pipe->socket());
          return false;
        }

        if (state == EIOState::E_COMPLETE) {
          os_layer->signal_io_complete(EPipeOperation::E_SEND);

          // Send is complete
          data.m_bytes_processed = 0;
          delete[] data.m_proc_buf;
          data.m_proc_buf = nullptr;
          return true;
        }

        // Incomplete still?
        return true;
      }
      else {
        os_layer->signal_io_complete(EPipeOperation::E_SEND);

        // Send is complete
        data.m_bytes_processed = 0;
        delete[] data.m_proc_buf;
        data.m_proc_buf = nullptr;
        return true;
      }
    }
    case EPipeOperation::E_CLOSE: {
      pipe->close();
      return true;
    }
    }

    return false;
  }

  void TCP_Server::integrate_pending_sockets() {
    while (!m_awaiting_sockets.empty()) {
      uint64_t socket = m_awaiting_sockets.front();
      m_awaiting_sockets.pop();

      ISecurityController* controller = nullptr;
      if (m_security) {
        controller = m_security->create_controller();
      }

      ISocketPipe* client_pipe = new TCP_Socket(
        m_server_socket, &m_recv_allocator, &m_send_allocator, controller, ESocketHint::E_SERVER);

      client_pipe->open(socket);
      client_pipe->clone_callbacks_from(m_server_socket);

      if (m_security) {
        m_pending_auth_sockets[socket] = SocketProcData(client_pipe);
        /*{
          TLS_SocketProxy* proxy = static_cast<TLS_SocketProxy*>(client_pipe);
          SocketLock l = proxy->acquire_lock();
          proxy->set_accept_state();
        }*/
      }
      else {
        m_client_sockets[socket] = SocketProcData(client_pipe);
      }
    }
  }

  void TCP_Server::proc_auth_on_sockets() {
    for (auto& socket : m_pending_auth_sockets) {
      ISocketPipe* pipe = socket.second.m_pipe;
      if (pipe == nullptr) {
        continue;
      }
    }
  }

  void TCP_Server::receive_on_sockets() {
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);

    for (auto& socket : m_client_sockets) {
      ISocketPipe* pipe = socket.second.m_pipe;
      if (pipe->is_busy(EPipeOperation::E_RECV)) {
        continue;
      }

      EIOState state = pipe->recv(0, nullptr, nullptr);
      if (state == EIOState::E_BUSY) {
        pipe->error(ESocketErrorReason::E_REASON_RECV);
        continue;
      }

      if (state == EIOState::E_ERROR) {
        pipe->error(ESocketErrorReason::E_REASON_RECV);
        continue;
      }
    }
  }

  void TCP_Server::cleanup_sockets() {
    std::scoped_lock<std::recursive_mutex> lock(m_mutex);

    while (!m_purgatory_sockets.empty()) {
      uint64_t socket = m_purgatory_sockets.front();
      m_purgatory_sockets.pop();

      if (m_client_sockets.find(socket) == m_client_sockets.end()) {
        continue;
      }

      SocketProcData& sock_data = m_client_sockets[socket];
      if (sock_data.m_pipe) {
        delete sock_data.m_pipe;

        // Pipe cleaned itself up earlier by the call to close
        m_client_sockets.erase(socket);
      }
    }
  }

  uint64_t TCP_Server::server_accept_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (server->is_running()) {
      bool success = server->m_server_socket->accept(nullptr, [server](uint64_t socket) {
        std::scoped_lock<std::recursive_mutex> lock(server->m_mutex);

        ISecurityController* controller = nullptr;
        if (server->m_security) {
          controller = server->m_security->create_controller();
        }

        ISocketPipe* client_pipe = new TCP_Socket(
          server->m_server_socket, &server->m_recv_allocator, &server->m_send_allocator, controller, ESocketHint::E_SERVER);

        client_pipe->open(socket);
        client_pipe->clone_callbacks_from(server->m_server_socket);

        if (server->m_security) {
          server->m_pending_auth_sockets[socket] = SocketProcData(client_pipe);

          controller->set_accept_state();
          client_pipe->proc_pending_auth(EPipeOperation::E_NONE, 0);
          //{
          //  TLS_SocketProxy* proxy = static_cast<TLS_SocketProxy*>(client_pipe);
          //  {
          //    SocketLock l = proxy->acquire_lock();
          //    proxy->set_accept_state();
          //  }
          //  proxy->proc_pending_auth(EPipeOperation::E_NONE, 0);
          //}
        }
        else {
          server->m_client_sockets[socket] = SocketProcData(client_pipe);
        }

        return true;
        });
    }

    return 0;
  }

  uint64_t TCP_Server::server_update_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    ISocketPipe* server_pipe = server->m_server_socket;

    while (server->is_running()) {
      server->integrate_pending_sockets();

      if (!server_pipe->notify_all()) {
        return 0;
      }

      server->proc_auth_on_sockets();
      server->receive_on_sockets();
    }

    return 0;
  }

  uint64_t TCP_Server::server_process_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    ISocketPipe* server_pipe = server->m_server_socket;

    // TODO: Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    while (server->is_running()) {
      server->cleanup_sockets();

      //printf("Num sockets: %lu\n", server->m_client_sockets.size());

      ISocketIOResult* sock_results = server->m_server_socket->wait_results();
      if (!sock_results || !sock_results->is_valid()) {
        server->m_server_socket->error(ESocketErrorReason::E_REASON_CORRUPT);
        goto exit_thread;
      }

      if (!sock_results->is_valid()) {
        server->m_server_socket->error(ESocketErrorReason::E_REASON_CORRUPT);
        delete sock_results;
        goto exit_thread;
      }

      std::scoped_lock<std::recursive_mutex> lock(server->m_mutex);

      sock_results->for_each([server](ISocketOSSupportLayer* pipe, const ISocketIOResult::OperationData& info) {
        bool is_disconnect = info.m_bytes_transferred == 0;
        if (is_disconnect) {
          pipe->close();
          return true;
        }

        if (server->m_client_sockets.find(pipe->socket()) == server->m_client_sockets.end()) {
          if (server->m_pending_auth_sockets.find(pipe->socket()) == server->m_pending_auth_sockets.end()) {
            return false;
          }
          return server->handle_auth_operations(server->m_pending_auth_sockets[pipe->socket()], info);
        }

        return server->handle_client_operations(server->m_client_sockets[pipe->socket()], info);
        });  // End of completion for loop

      delete sock_results;
    }  // End of while loop

  exit_thread:
    return 0;
  }

}  // namespace netpp

#include <chrono>
#include <iostream>
#include <thread>

#include "network.h"
#include "socket.h"

#include "server.h"

using namespace std::chrono;
using namespace std::chrono_literals;

#ifdef _WIN32

#include <MSWSock.h>

#define RIO_PENDING_MAX 5
#define RIO_MAX_BUFFERS 1024

#define SKIP_BUF_INIT_FLAG 0x80000000

enum class ESocketOperation : DWORD {
  E_SEND,
  E_RECV,
  E_CLOSE,
};

enum class ECompletionKey : DWORD {
  E_STOP,
  E_START,
};

struct Tag_RIO_BUF : public RIO_BUF {
  Tag_RIO_BUF(RIO_BUFFERID buffer_id, DWORD offset, DWORD length, ESocketOperation operation, netpp::ISocketOSSupportLayer* owner) {
    this->BufferId = buffer_id;
    this->Offset = offset;
    this->Length = length;
    this->Operation = operation;
    this->Pipe = owner;
    this->IsBusy = FALSE;
  }

  ESocketOperation Operation;
  netpp::ISocketOSSupportLayer* Pipe;
  BOOL IsBusy;
};

class Win32ServerSocketLayer : public netpp::ISocketOSSupportLayer {
public:
  Win32ServerSocketLayer(netpp::IServer* server,
    netpp::StaticBlockAllocator* recv_allocator, netpp::StaticBlockAllocator* send_allocator,
    RIO_EXTENSION_FUNCTION_TABLE rio) {
    m_socket = INVALID_SOCKET;
    m_recv_buffer = new Tag_RIO_BUF{
      RIO_BUFFERID{ RIO_INVALID_BUFFERID },
      0,
      0,
      ESocketOperation::E_RECV,
      this
    };
    m_send_buffer = new Tag_RIO_BUF{
      RIO_BUFFERID{ RIO_INVALID_BUFFERID },
      0,
      0,
      ESocketOperation::E_SEND,
      this
    };
    m_completion_queue = RIO_INVALID_CQ;
    m_request_queue = RIO_INVALID_RQ;
    m_iocp = INVALID_HANDLE_VALUE;
    m_overlapped = { 0 };
    m_server = server;
  }

  ~Win32ServerSocketLayer() override {
    delete m_recv_buffer;
    delete m_send_buffer;

    if (m_socket != INVALID_SOCKET) {
      ::shutdown(m_socket, SD_BOTH);
      ::closesocket(m_socket);
      m_socket = INVALID_SOCKET;
    }
  }

  bool is_busy(netpp::EPipeOperation op) const override {
    switch (op) {
    case netpp::EPipeOperation::E_RECV:
      return m_recv_buffer->IsBusy;
    case netpp::EPipeOperation::E_SEND:
      return m_send_buffer->IsBusy;
    case netpp::EPipeOperation::E_BOTH:
      return m_recv_buffer->IsBusy || m_send_buffer->IsBusy;
    }
  }

  void set_busy(netpp::EPipeOperation op, bool busy) override {
    switch (op) {
    case netpp::EPipeOperation::E_RECV:
      m_recv_buffer->IsBusy = busy;
      return;
    case netpp::EPipeOperation::E_SEND:
      m_send_buffer->IsBusy = busy;
      return;
    case netpp::EPipeOperation::E_BOTH:
      m_recv_buffer->IsBusy = busy;
      m_send_buffer->IsBusy = busy;
      return;
    }
  }

  bool open(const char* hostname, const char* port) override {
    if (!m_server) {
      return false;
    }

    Win32ServerSocketLayer* server_pipe = (Win32ServerSocketLayer*)m_server->get_os_layer();
    if (!server_pipe) {
      return false;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    inet_pton(AF_INET, hostname, &addr.sin_addr);

    uint64_t socket_ = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
    if (socket_ == INVALID_SOCKET) {
      return false;
    }

    ZeroMemory(&m_overlapped, sizeof(OVERLAPPED));

    m_recv_buf_block = m_recv_allocator->allocate();
    m_recv_buffer = new Tag_RIO_BUF(*server_pipe->m_recv_buffer);
    m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block);
    m_recv_buffer->Pipe = this;

    m_send_buf_block = m_send_allocator->allocate();
    m_send_buffer = new Tag_RIO_BUF(*server_pipe->m_send_buffer);
    m_send_buffer->Offset = m_send_allocator->ofs(m_send_buf_block);
    m_send_buffer->Pipe = this;

    m_completion_queue = server_pipe->m_completion_queue;
    m_completion_queue = server_pipe->m_completion_queue;

    m_request_queue = m_rio->RIOCreateRequestQueue(
      socket_,
      RIO_PENDING_MAX, 1,
      RIO_PENDING_MAX, 1,
      m_completion_queue,
      m_completion_queue,
      this
    );

    m_iocp = server_pipe->m_iocp;
    m_socket = socket_;
    return true;
  }

  void close() override {
    if (!m_on_close(this)) {
      ::shutdown(m_socket, SD_BOTH);
      ::closesocket(m_socket);

      m_recv_allocator->deallocate(m_recv_buf_block);
      m_send_allocator->deallocate(m_send_buf_block);
    }
  }

  void error(netpp::ESocketErrorReason reason) override {
    if (!m_on_error(this, reason)) {
      fprintf(stderr, "Unhandled error (%d)", (int)reason);
    }
  }

  bool sync(uint64_t wait_time) override {
    if (wait_time == 0) {
      while (is_busy(netpp::EPipeOperation::E_BOTH)) {
        std::this_thread::sleep_for(10ms);
      }
      return true;
    }

    time_point<high_resolution_clock> start_time = high_resolution_clock::now();
    while (is_busy(netpp::EPipeOperation::E_BOTH)) {
      time_point<high_resolution_clock> now_time = high_resolution_clock::now();
      if ((now_time - start_time).count() > wait_time) {
        return false;
      }
      std::this_thread::sleep_for(10ms);
    }

    return true;
  }

  bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    if (m_recv_buffer->IsBusy) {
      return FALSE;
    }

    m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block) + offset;

    BOOL rc = m_rio->RIOReceive(m_request_queue, m_recv_buffer, 1, NULL, m_recv_buffer);
    if (rc) {
      m_recv_buffer->IsBusy = TRUE;
    }
    return rc;
  }

  bool send(const char* data, uint32_t size, uint32_t* flags) {
    if (m_send_buffer->IsBusy) {
      return FALSE;
    }

    char* send_buf = (char*)m_send_allocator->ptr(m_send_buf_block);
    uint32_t block_size = m_send_allocator->block_size();

    uint32_t chunk_size = min(size, block_size);
    memcpy_s(send_buf, (size_t)block_size, data, chunk_size);
    m_send_buffer->Length = (ULONG)chunk_size;

    uint32_t flags_ = flags ? *flags : 0;

    BOOL rc = m_rio->RIOSend(m_request_queue, m_send_buffer, 1, flags_ & ~SKIP_BUF_INIT_FLAG, m_send_buffer);
    if (rc) {
      if ((flags_ & SKIP_BUF_INIT_FLAG) == 0) {
        m_send_data = data;
        m_send_size = size;
      }
      m_send_buffer->IsBusy = TRUE;
    }
    return rc;
  }

private:
  netpp::IServer* m_server;
  netpp::StaticBlockAllocator* m_recv_allocator;
  netpp::StaticBlockAllocator* m_send_allocator;
  close_cb m_on_close;
  error_cb m_on_error;

  SOCKET m_socket;

  uint32_t m_recv_buf_block;
  Tag_RIO_BUF* m_recv_buffer;

  uint32_t m_send_buf_block;
  Tag_RIO_BUF* m_send_buffer;

  RIO_EXTENSION_FUNCTION_TABLE *m_rio;

  RIO_CQ m_completion_queue;
  RIO_RQ m_request_queue;
  HANDLE m_iocp;
  OVERLAPPED m_overlapped;

  // For chunking data into the buffer
  const char* m_send_data;
  uint32_t m_send_size;
  uint32_t m_send_offset;
};

namespace netpp {

  bool TCP_Socket::open(const char* hostname, const char* port) {
    return m_pipe->open(hostname, port);
  }

  void TCP_Socket::close() {
    m_pipe->close();
  }

  bool TCP_Socket::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    return m_pipe->recv(offset, flags, transferred_out);
  }

  bool TCP_Socket::proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    uint8_t* tag = (uint8_t*)(in_data + iv_size);
    uint8_t* iv = (uint8_t*)in_data;

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, tag, iv);

    uint32_t offset = iv_size + tag_size;

    if (in_size <= offset) {
      return false;
    }

    // Cyphertext decryption
    int _in_s = (int)in_size;
    int _out_s;
    EVP_DecryptUpdate(ctx, (uint8_t*)out_data, &_out_s, (uint8_t*)(in_data + offset), in_size - offset);

    // Set the expected auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, tag);

    int ret = EVP_DecryptFinal_ex(ctx, (uint8_t*)(out_data + _out_s), &_out_s);

    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
  }

  // Application surrenders ownership of the buffer
  bool TCP_Socket::send(const char* data, uint32_t size, uint32_t* flags) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    uint32_t crypt_size = iv_size + tag_size + size;
    uint8_t* crypt_data = (uint8_t*)malloc(crypt_size);

    // Initialize the iv descriptor
    RAND_bytes(crypt_data, iv_size);

    // Encryption initialization
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, m_aes_key, crypt_data);

    int _in_size = (int)size;

    // Plaintext encryption
    int out_size;
    EVP_EncryptUpdate(ctx, crypt_data + iv_size + tag_size, &out_size, (uint8_t*)data, size);

    if (crypt_size != out_size + tag_size) {
      return false;
    }

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, crypt_data + size, &out_size);

    if (out_size != tag_size) {
      return false;
    }

    // Get auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, crypt_data + iv_size);

    m_pipe->send((const char*)crypt_data, crypt_size, flags);

    EVP_CIPHER_CTX_free(ctx);
    return true;
  }

  bool TCP_Socket::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TCP_Socket::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TCP_Socket::send(const RawPacket* packet) {
    return send(packet->message(), packet->length(), nullptr);
  }

}  // namespace netpp

#endif
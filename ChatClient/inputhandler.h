#pragma once

#include <functional>
#include <iostream>
#include <string>
#include <thread>

class InputHandler {
public:
  using message_callback = std::function<bool(const std::string& message)>;

  InputHandler() = delete;
  InputHandler(const std::string& client_name) {
    m_client_name = client_name;
  }
  virtual ~InputHandler() = default;

  void flag_processed() {
    m_msg_processed = true;
  }

  void start() {
    m_running = true;
    m_thread = std::thread(io_thread, this);
  }

  void stop() {
    m_running = false;
    if (m_thread.joinable()) {
      m_thread.join();
    }
  }

  void print_prompt() {
    printf("\n------------------------------\nClient (%s) => ", m_client_name.c_str());
  }

  void on_message_submit(message_callback cb) {
    m_message_cb = cb;
  }

protected:
  static void io_thread(InputHandler* handler) {
    while (handler->m_running) {
      if (!handler->m_msg_processed) {
        continue;
      }

      handler->print_prompt();

      std::string message;
      std::getline(std::cin, message);
      if (handler->m_message_cb) {
        handler->m_msg_processed = false;
        if (!handler->m_message_cb(message)) {
          handler->m_running = false;
          break;
        }
      }
    }
  }

private:
  bool m_msg_processed = true;
  bool m_running = false;
  std::string m_client_name;
  std::thread m_thread;
  message_callback m_message_cb;
};
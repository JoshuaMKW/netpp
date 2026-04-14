#pragma once

#include <string>
#include <vector>

#include "netpp.h"

namespace netpp {

    class DNS_Question {
    public:
        friend class DNS_Message;
        // ...
    };

    class DNS_Answer {
    public:
        friend class DNS_Message;
        // ...
    };

    class DNS_Message {
    public:
        DNS_Message() = delete;
        DNS_Message(const DNS_Message&) = default;
        DNS_Message(DNS_Message&&) noexcept = default;

        static bool is_data_query(const char* msg_buf, uint32_t buf_size);
        static bool is_data_response(const char* msg_buf, uint32_t buf_size);

        static DNS_Message* create_query();
        static DNS_Message* create_response();

        static const char* build_buf(const DNS_Message& msg, uint32_t* size_out);

        const std::vector<DNS_Question>& questions() const { return m_questions; }
        const std::vector<DNS_Answer>& answers() const { return m_answers; }

    private:
        std::vector<DNS_Question> m_questions;
        std::vector<DNS_Answer> m_answers;
    };

}
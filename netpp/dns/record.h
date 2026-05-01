#pragma once

#include <limits>
#include <string>
#include <vector>

#include "netpp.h"

namespace netpp {

std::string get_reverse_lookup_domain_name(const char* ip_addr);

// RFC1035 - 3.2.2
enum class EDNSQuery_RR_TYPE : uint16_t {
    TYPE_A = 1, // Host address
    TYPE_NS = 2, // Authoritative Name Server
    TYPE_MD = 3, // Mail Destination
    TYPE_MF = 4, // Mail Forwarder
    TYPE_CNAME = 5, // Canonical Name for Alias
    TYPE_SOA = 6, // Marks the Start of a Zone of Authority
    TYPE_MB = 7, // Mailbox Domain Name (EXPERIMENTAL)
    TYPE_MG = 8, // Mailbox Group Member (EXPERIMENTAL)
    TYPE_MR = 9, // Mailbox Rename Domain Name (EXPERIMENTAL)
    TYPE_NULL = 10, // NULL RR (EXPERIMENTAL)
    TYPE_WKS = 11, // Well Known Service Description
    TYPE_PTR = 12, // Reverse-lookup
    TYPE_HINFO = 13, // Host Information
    TYPE_MINFO = 14, // Mailbox or List Information
    TYPE_MX = 15, // Mail Exchange
    TYPE_TXT = 16, // Text Strings
    TYPE_AAAA = 28, // Host address (IPV6)

    // [DNSSEC] - RFC4033, RFC4034, RFC4035
    TYPE_DS = 43, // DNSKEY RR pointer stored in parental zone for child zone
    TYPE_RRSIG = 46, // Digital signature for DNSSEC verification
    TYPE_NSEC = 47, // Next security info
    TYPE_DNSKEY = 48, // Public key for DNS security

    TYPE_MAX = std::numeric_limits<uint16_t>::max(),
};

// RFC1035 - 3.2.3
enum class EDNSQuery_RR_QTYPE : uint16_t {
    TYPE_A = 1, // Host address
    TYPE_NS = 2, // Authoritative Name Server
    TYPE_MD = 3, // Mail Destination
    TYPE_MF = 4, // Mail Forwarder
    TYPE_CNAME = 5, // Canonical Name for Alias
    TYPE_SOA = 6, // Marks the Start of a Zone of Authority
    TYPE_MB = 7, // Mailbox Domain Name (EXPERIMENTAL)
    TYPE_MG = 8, // Mailbox Group Member (EXPERIMENTAL)
    TYPE_MR = 9, // Mailbox Rename Domain Name (EXPERIMENTAL)
    TYPE_NULL = 10, // NULL RR (EXPERIMENTAL)
    TYPE_WKS = 11, // Well Known Service Description
    TYPE_PTR = 12, // Reverse-lookup
    TYPE_HINFO = 13, // Host Information
    TYPE_MINFO = 14, // Mailbox or List Information
    TYPE_MX = 15, // Mail Exchange
    TYPE_TXT = 16, // Text Strings
    TYPE_AAAA = 28, // Host address (IPV6)
    TYPE_DNSKEY = 48, // Public key for DNS security

    QTYPE_IXFR = 251, // Incremental Zone Transfer
    QTYPE_AXFR = 252, // Standard Zone Transfer
    QTYPE_MAILB = 253, // Request for Mailbox records (MB, MG, or MR)
    QTYPE_MAILA = 254, // Request for Mail Agent Records (Obsolete - see MX)
    QTYPE_ALL = 255, // All Records

    QTYPE_MAX = std::numeric_limits<uint16_t>::max(),
};

// RFC1035 - 3.2.4
enum class EDNSQuery_RR_CLASS : uint16_t {
    CLASS_IN = 1, // Internet, default
    CLASS_CS = 2, // CSNET, (Obsolete - used only for examples in some obsolete RFCs)
    CLASS_CH = 3, // CHAOS
    CLASS_HS = 4, // Hesiod [Dyer 87]
};

// RFC1035 - 3.2.5
enum class EDNSQuery_RR_QCLASS : uint16_t {
    CLASS_IN = 1, // Internet, default
    CLASS_CS = 2, // CSNET, (Obsolete - used only for examples in some obsolete RFCs)
    CLASS_CH = 3, // CHAOS
    CLASS_HS = 4, // Hesiod [Dyer 87]

    QCLASS_ALL = 255, // Any Class
};

enum class EDNSQuery_OperationCode {
    OPERATION_QUERY = 0,
    OPERATION_REGISTRATION = 5,
    OPERATION_RELEASE = 6,
    OPERATION_WACK = 7,
    OPERATION_REFRESH = 8,
};

enum class EDNSQuery_ReturnCode {
    RETURN_SUCCESS = 0,
    RETURN_FORMAT_ERROR = 1,
    RETURN_SERVER_FAILURE = 2,
    RETURN_NAME_ERROR = 3,
    RETURN_NOT_IMPLEMENTED = 4,
    RETURN_REFUSED = 5,
};

// Opaque base for inherited instances that represent each RDATA
class DNS_RData { };

struct DNS_StorerState {
    std::vector<uint8_t> m_out;
    uint32_t m_header_idx;
    std::unordered_map<std::string, uint16_t> m_dname_to_pointer_cache;
};
using DNS_RR_Loader = DNS_RData* (*)(const void* header, uint32_t rdlength, const void* rdata, EDNSQuery_RR_CLASS);
using DNS_RR_Storer = uint16_t (*)(DNS_StorerState&, DNS_RData*, EDNSQuery_RR_CLASS);

class DNS_Question {
public:
    friend class DNS_Message;

    DNS_Question() = delete;
    DNS_Question(const std::string& name, EDNSQuery_RR_QTYPE type, EDNSQuery_RR_QCLASS klass);

    const std::string& name() const noexcept { return m_name; }
    EDNSQuery_RR_QCLASS klass() const noexcept { return m_class; }
    EDNSQuery_RR_QTYPE type() const noexcept { return m_type; }

private:
    std::string m_name;
    EDNSQuery_RR_QCLASS m_class;
    EDNSQuery_RR_QTYPE m_type;
};

class DNS_Record {
public:
    friend class DNS_Message;

    DNS_Record() = delete;
    DNS_Record(const std::string& name, EDNSQuery_RR_TYPE type, EDNSQuery_RR_CLASS klass, uint32_t ttl, DNS_RData* data);

    const std::string& name() const noexcept { return m_name; }
    EDNSQuery_RR_CLASS klass() const noexcept { return m_class; }
    EDNSQuery_RR_TYPE type() const noexcept { return m_type; }
    uint32_t ttl() const noexcept { return m_ttl; }
    const DNS_RData* rdata() const noexcept { return m_rdata; }

private:
    std::string m_name;
    EDNSQuery_RR_CLASS m_class;
    EDNSQuery_RR_TYPE m_type;
    uint32_t m_ttl;
    DNS_RData* m_rdata;
};

class DNS_Message {
public:
    DNS_Message(const DNS_Message&) = default;
    DNS_Message(DNS_Message&&) noexcept = default;

protected:
    DNS_Message() = default;

public:
    static bool is_data_query(const char* msg_buf, uint32_t buf_size);
    static bool is_data_response(const char* msg_buf, uint32_t buf_size);

    static DNS_Message* create_query(uint16_t transaction_id);
    static DNS_Message* create_response(const DNS_Message* query);
    static DNS_Message* create(const char* dns_buf, int buflen);

    static const char* build_buf(const DNS_Message& msg, uint32_t* size_out);

    void set_id(uint16_t id) { m_id = id; }
    uint16_t id() const { return m_id; }

    void set_flags(uint16_t flags) { m_flags = flags; }
    uint16_t flags() const { return m_flags; }

    void add_question(const DNS_Question& q) { m_questions.push_back(q); }
    void add_answer(const DNS_Record& r) { m_answers.push_back(r); }
    void add_authoritative(const DNS_Record& r) { m_authoritatives.push_back(r); }
    void add_additional(const DNS_Record& r) { m_additionals.push_back(r); }

    const std::vector<DNS_Question>& questions() const { return m_questions; }
    const std::vector<DNS_Record>& answers() const { return m_answers; }
    const std::vector<DNS_Record>& authoritatives() const { return m_authoritatives; }
    const std::vector<DNS_Record>& additionals() const { return m_additionals; }

private:
    uint16_t m_id;
    uint16_t m_flags;
    std::vector<DNS_Question> m_questions;
    std::vector<DNS_Record> m_answers;
    std::vector<DNS_Record> m_authoritatives;
    std::vector<DNS_Record> m_additionals;
};

// ------ RDATA INSTANCES ------ //

class DNS_RData_CNAME final : public DNS_RData {
public:
    DNS_RData_CNAME() = delete;
    DNS_RData_CNAME(const std::string& cname)
        : m_cname(cname)
    {
    }

    const std::string& cname() const noexcept
    {
        return m_cname;
    }

private:
    std::string m_cname;
};

class DNS_RData_HINFO final : public DNS_RData {
public:
    DNS_RData_HINFO() = delete;
    DNS_RData_HINFO(const std::string& cpu, const std::string& os)
        : m_cpu(cpu)
        , m_os(os)
    {
    }

    const std::string& cpu() const noexcept
    {
        return m_cpu;
    }

    const std::string& os() const noexcept
    {
        return m_os;
    }

private:
    std::string m_cpu;
    std::string m_os;
};

class DNS_RData_MB final : public DNS_RData {
public:
    DNS_RData_MB() = delete;
    DNS_RData_MB(const std::string& madname)
        : m_madname(madname)
    {
    }

    const std::string& madname() const noexcept
    {
        return m_madname;
    }

private:
    std::string m_madname;
};

class DNS_RData_MD final : public DNS_RData {
public:
    DNS_RData_MD() = delete;
    DNS_RData_MD(const std::string& madname)
        : m_madname(madname)
    {
    }

    const std::string& madname() const noexcept
    {
        return m_madname;
    }

private:
    std::string m_madname;
};

class DNS_RData_MF final : public DNS_RData {
public:
    DNS_RData_MF() = delete;
    DNS_RData_MF(const std::string& madname)
        : m_madname(madname)
    {
    }

    const std::string& madname() const noexcept
    {
        return m_madname;
    }

private:
    std::string m_madname;
};

class DNS_RData_MG final : public DNS_RData {
public:
    DNS_RData_MG() = delete;
    DNS_RData_MG(const std::string& mgmname)
        : m_mgmname(mgmname)
    {
    }

    const std::string& mgmname() const noexcept
    {
        return m_mgmname;
    }

private:
    std::string m_mgmname;
};

class DNS_RData_MINFO final : public DNS_RData {
public:
    DNS_RData_MINFO() = delete;
    DNS_RData_MINFO(const std::string& rmailbx, const std::string& emailbx)
        : m_rmailbx(rmailbx)
        , m_emailbx(emailbx)
    {
    }

    const std::string& rmailbx() const noexcept
    {
        return m_rmailbx;
    }

    const std::string& emailbx() const noexcept
    {
        return m_emailbx;
    }

private:
    std::string m_rmailbx;
    std::string m_emailbx;
};

class DNS_RData_MR final : public DNS_RData {
public:
    DNS_RData_MR() = delete;
    DNS_RData_MR(const std::string& newname)
        : m_newname(newname)
    {
    }

    const std::string& newname() const noexcept
    {
        return m_newname;
    }

private:
    std::string m_newname;
};

class DNS_RData_MX final : public DNS_RData {
public:
    DNS_RData_MX() = delete;
    DNS_RData_MX(uint16_t preference, const std::string& exchange)
        : m_preference(preference)
        , m_exchange(exchange)
    {
    }

    uint16_t preference() const noexcept
    {
        return m_preference;
    }

    const std::string& exchange() const noexcept
    {
        return m_exchange;
    }

private:
    uint16_t m_preference;
    std::string m_exchange;
};

class DNS_RData_NULL final : public DNS_RData {
public:
    DNS_RData_NULL() = delete;
    DNS_RData_NULL(const std::vector<uint8_t>& anything)
        : m_data(anything)
    {
    }

    const std::vector<uint8_t>& data() const noexcept
    {
        return m_data;
    }

private:
    std::vector<uint8_t> m_data;
};

class DNS_RData_NS final : public DNS_RData {
public:
    DNS_RData_NS() = delete;
    DNS_RData_NS(const std::string& nsdname)
        : m_nsdname(nsdname)
    {
    }

    const std::string& nsdname() const noexcept
    {
        return m_nsdname;
    }

private:
    std::string m_nsdname;
};

class DNS_RData_PTR final : public DNS_RData {
public:
    DNS_RData_PTR() = delete;
    DNS_RData_PTR(const std::string& ptrdname)
        : m_ptrdname(ptrdname)
    {
    }

    const std::string& ptrdname() const noexcept
    {
        return m_ptrdname;
    }

private:
    std::string m_ptrdname;
};

class DNS_RData_SOA final : public DNS_RData {
public:
    DNS_RData_SOA() = delete;
    DNS_RData_SOA(const std::string& mname, const std::string& rname, uint32_t serial,
        uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum)
        : m_mname(mname)
        , m_rname(rname)
        , m_serial(serial)
        , m_refresh(refresh)
        , m_retry(retry)
        , m_expire(expire)
        , m_minimum(minimum)
    {
    }

    const std::string& mname() const noexcept
    {
        return m_mname;
    }

    const std::string& rname() const noexcept
    {
        return m_rname; // Fixed from m_mname
    }

    uint32_t serial() const noexcept
    {
        return m_serial;
    }

    uint32_t refresh() const noexcept
    {
        return m_refresh;
    }

    uint32_t retry() const noexcept
    {
        return m_retry;
    }

    uint32_t expire() const noexcept
    {
        return m_expire;
    }

    uint32_t minimum() const noexcept
    {
        return m_minimum; // Fixed from m_expire
    }

private:
    std::string m_mname;
    std::string m_rname;
    uint32_t m_serial;
    uint32_t m_refresh;
    uint32_t m_retry;
    uint32_t m_expire;
    uint32_t m_minimum;
};

class DNS_RData_TXT final : public DNS_RData {
public:
    DNS_RData_TXT() = delete;
    DNS_RData_TXT(const std::vector<std::string>& txtdata)
        : m_txtdata(txtdata)
    {
    }

    const std::vector<std::string>& txtdata() const noexcept
    {
        return m_txtdata;
    }

private:
    std::vector<std::string> m_txtdata;
};

class DNS_RData_A final : public DNS_RData {
public:
    DNS_RData_A() = delete;
    DNS_RData_A(uint32_t address)
        : m_address(address)
    {
    }

    std::string ipv4() const;

    uint32_t address() const noexcept
    {
        return m_address;
    }

private:
    uint32_t m_address;
};

class DNS_RData_WKS final : public DNS_RData {
public:
    DNS_RData_WKS() = delete;
    DNS_RData_WKS(uint32_t address, uint8_t protocol, const std::vector<uint8_t>& bitmap)
        : m_address(address)
        , m_protocol(protocol)
        , m_bitmap(bitmap)
    {
    }

    std::string ipv4() const;

    uint32_t address() const noexcept
    {
        return m_address;
    }

    uint8_t protocol() const noexcept
    {
        return m_protocol;
    }

    const std::vector<uint8_t>& bitmap() const noexcept
    {
        return m_bitmap;
    }

private:
    uint32_t m_address;
    uint8_t m_protocol;
    std::vector<uint8_t> m_bitmap;
};

class DNS_RData_AAAA final : public DNS_RData {
public:
    DNS_RData_AAAA() = delete;
    DNS_RData_AAAA(uint64_t upper, uint64_t lower)
        : m_upper(upper)
        , m_lower(lower)
    {
    }

    std::string ipv6() const;

    uint64_t address_upper() const noexcept
    {
        return m_upper;
    }

    uint64_t address_lower() const noexcept
    {
        return m_lower;
    }

private:
    uint64_t m_upper;
    uint64_t m_lower;
};

class DNS_RData_DNSKEY final : public DNS_RData {
public:
    DNS_RData_DNSKEY() = delete;
    DNS_RData_DNSKEY(uint16_t flags, uint8_t protocol, uint8_t algorithm, const std::vector<uint8_t>& pubkey)
        : m_flags(flags)
        , m_protocol(protocol)
        , m_algorithm(algorithm)
        , m_pubkey(pubkey)
    {
    }

    std::string ipv6() const;

    uint16_t flags() const noexcept
    {
        return m_flags;
    }

    uint8_t protocol() const noexcept
    {
        return m_protocol;
    }

    uint8_t algorithm() const noexcept
    {
        return m_algorithm;
    }

    const std::vector<uint8_t>& pubkey() const noexcept
    {
        return m_pubkey;
    }

private:
    uint16_t m_flags;
    uint8_t m_protocol;
    uint8_t m_algorithm;
    std::vector<uint8_t> m_pubkey;
};

class DNS_RData_RRSIG final : public DNS_RData {
public:
    DNS_RData_RRSIG() = delete;
    DNS_RData_RRSIG(netpp::EDNSQuery_RR_TYPE type_covered, uint8_t algorithm, uint8_t labels, uint32_t original_ttl, uint32_t sig_expiration, uint32_t sig_inception, uint16_t key_tag, const std::string& signers_name, const std::vector<uint8_t>& signature)
        : m_type_covered(type_covered)
        , m_algorithm(algorithm)
        , m_labels(labels)
        , m_original_ttl(original_ttl)
        , m_sig_expiration(sig_expiration)
        , m_sig_inception(sig_inception)
        , m_key_tag(key_tag)
        , m_signers_name(signers_name)
        , m_signature(signature)
    {
    }

    netpp::EDNSQuery_RR_TYPE type_covered() const
    {
        return m_type_covered;
    }

    uint8_t algorithm() const noexcept
    {
        return m_algorithm;
    }

    uint8_t labels() const noexcept
    {
        return m_labels;
    }

    uint32_t original_ttl() const noexcept
    {
        return m_original_ttl;
    }

    uint32_t sig_expiration() const noexcept
    {
        return m_sig_expiration;
    }

    uint32_t sig_inception() const noexcept
    {
        return m_sig_inception;
    }

    uint16_t key_tag() const noexcept
    {
        return m_key_tag;
    }

    const std::string& signers_name() const noexcept
    {
        return m_signers_name;
    }

    const std::vector<uint8_t>& signature() const noexcept
    {
        return m_signature;
    }

private:
    netpp::EDNSQuery_RR_TYPE m_type_covered;
    uint8_t m_algorithm;
    uint8_t m_labels;
    uint32_t m_original_ttl;
    uint32_t m_sig_expiration;
    uint32_t m_sig_inception;
    uint16_t m_key_tag;
    std::string m_signers_name;
    std::vector<uint8_t> m_signature;
};

}
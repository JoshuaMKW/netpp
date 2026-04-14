// ------------------------------------
// The following code is based on
// RFC1035 and the Microsoft Docs
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <iostream>
#include <numbers>
#include <string>

#include "../netpp.h"
#include "record.h"

// ------------------------------------
// See: RFC1035 - 2.3.4.
// ------------------------------------
#define DNS_LABEL_OCTET_LIMIT 63
#define DNS_NAME_OCTET_LIMIT 255
#define DNS_TTL_LIMIT 4294967295
#define DNS_UDP_OCTET_LIMIT 512
// ------------------------------------

#define DNS_UPPER_OCTET(octet_pair) (uint8_t)(octet_pair >> 8)
#define DNS_LOWER_OCTET(octet_pair) (uint8_t)(octet_pair)

static uint16_t _DNS_ReadUnaligned16(const void* ptr) {
    uint16_t val;
    std::memcpy(&val, ptr, sizeof(uint16_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

static uint32_t _DNS_ReadUnaligned32(const void* ptr) {
    uint32_t val;
    std::memcpy(&val, ptr, sizeof(uint32_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

static void _DNS_WriteUnaligned16(void* ptr, uint16_t val) {
    uint16_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint16_t));
}

static void _DNS_WriteUnaligned32(void* ptr, uint32_t val) {
    uint32_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint32_t));
}

// ------------------------------------
// See: RFC1035 - 2.3.3.
// ------------------------------------
static int DNS_StringCompareInsensitive(const std::string& l, const std::string& r) {
  int difference = 0;

  size_t boundary = std::min(l.size(), r.size());
  for (size_t i = 0; i < boundary; ++i) {
    int li = ::tolower((int)l[i]);
    int ri = ::tolower((int)r[i]);
    difference += li - ri;
  }

  return difference;

}//-------------------
// RFC1035 - 2.3.1 & 3.1 & 4.1.4
// -------------------
static std::string DNSQuery_GetDomainName(DNSQuery_MessageHeader* h, uint8_t* enc_data) {
    std::string result;
    result.reserve(DNS_NAME_OCTET_LIMIT);

    int32_t pointers_chased = 0;

    while (result.length() < DNS_NAME_OCTET_LIMIT) {
        const bool is_compressed = (enc_data[0] & 0b11000000) == 0b11000000;
        uint8_t token_length = (enc_data[0] & 0b00111111);

        if (is_compressed) {
            if (pointers_chased >= 10) {
                break;  // We exit early to avoid malicious attacks
            }

            // token length and the next byte is the pointer offset in this case
            uint16_t pointer_offset = (token_length << 8) | (enc_data[1]);
            enc_data = (uint8_t*)h + pointer_offset;
            pointers_chased += 1;
            continue;
        }

        enc_data += 1;

        // NULL terminator
        if (token_length == 0) {
            break;
        }

        if (!result.empty()) {
            result.append(".");
        }

        result.append((const char*)enc_data, token_length);
        enc_data += token_length;
    }

    return result;
}

static uint8_t DNSQuery_GetDomainNameCompressedSize(uint8_t* enc_data) {
    uint16_t length = 0;
    while (length < DNS_NAME_OCTET_LIMIT) {
        const bool is_compressed = (enc_data[0] & 0b11000000) == 0b11000000;
        uint8_t token_length = (enc_data[0] & 0b00111111);

        if (is_compressed) {
            length += 2; // compressed pointer is 2 bytes
            break;
        }

        // NULL terminator
        if (token_length == 0) {
            length += 1;
            break;
        }

        length += 1 + token_length;
        enc_data += 1 + token_length;
    }

    if (length > DNS_NAME_OCTET_LIMIT) {
        fprintf(stderr, "Warning: Domain name length exceeds limit, truncating to %d bytes\n", DNS_NAME_OCTET_LIMIT);
        return DNS_NAME_OCTET_LIMIT;
    }

    return static_cast<uint8_t>(length);
}

static uint8_t DNSQuery_GetDomainNameLength(DNSQuery_MessageHeader* h, uint8_t* enc_data) {
    uint16_t length = 0;
    while (length < DNS_NAME_OCTET_LIMIT) {
        const bool is_compressed = (enc_data[0] & 0b11000000) == 0b11000000;
        uint8_t token_length = (enc_data[0] & 0b00111111);

        if (is_compressed) {
            uint16_t pointer_offset = (token_length << 8) | (enc_data[1]);
            enc_data = (uint8_t*)h + pointer_offset;
            continue;
        }

        // NULL terminator
        if (token_length == 0) {
            break;
        }

        length += token_length;
        enc_data += token_length;
    }

    if (length > DNS_NAME_OCTET_LIMIT) {
        fprintf(stderr, "Warning: Domain name length exceeds limit, truncating to %d bytes\n", DNS_NAME_OCTET_LIMIT);
        return DNS_NAME_OCTET_LIMIT;
    }

    return static_cast<uint8_t>(length);
}

static std::string DNSQuery_GetCharacterString(uint8_t* enc_data) {
  const uint8_t token_length = (*enc_data & 0b11111111); // Is already <= DNS_NAME_OCTET_LIMIT due to the 1 byte length prefix
  return std::string((const char*)(enc_data + 1), token_length);
}

static uint16_t DNSQuery_GetCharacterStringLength(uint8_t* enc_data) {
  uint16_t length = *enc_data;
  return std::min<uint16_t>(length + 1, DNS_NAME_OCTET_LIMIT);
}
// -----------------

// RFC1035 - 3.2.2
enum EDNSQuery_RR_TYPE : uint16_t {
  TYPE_A = 1,       // Host address
  TYPE_NS = 2,      // Authoritative Name Server
  TYPE_MD = 3,      // Mail Destination
  TYPE_MF = 4,      // Mail Forwarder
  TYPE_CNAME = 5,   // Canonical Name for Alias
  TYPE_SOA = 6,     // Marks the Start of a Zone of Authority
  TYPE_MB = 7,      // Mailbox Domain Name (EXPERIMENTAL)
  TYPE_MG = 8,      // Mailbox Group Member (EXPERIMENTAL)
  TYPE_MR = 9,      // Mailbox Rename Domain Name (EXPERIMENTAL)
  TYPE_NULL = 10,   // NULL RR (EXPERIMENTAL)
  TYPE_WKS = 11,    // Well Known Service Description
  TYPE_PTR = 12,    // Reverse-lookup
  TYPE_HINFO = 13,  // Host Information
  TYPE_MINFO = 14,  // Mailbox or List Information
  TYPE_MX = 15,     // Mail Exchange
  TYPE_TXT = 16,    // Text Strings
};

// RFC1035 - 3.2.3
enum EDNSQuery_RR_QTYPE : uint16_t {
  TYPE_A = 1,       // Host address
  TYPE_NS = 2,      // Authoritative Name Server
  TYPE_MD = 3,      // Mail Destination
  TYPE_MF = 4,      // Mail Forwarder
  TYPE_CNAME = 5,   // Canonical Name for Alias
  TYPE_SOA = 6,     // Marks the Start of a Zone of Authority
  TYPE_MB = 7,      // Mailbox Domain Name (EXPERIMENTAL)
  TYPE_MG = 8,      // Mailbox Group Member (EXPERIMENTAL)
  TYPE_MR = 9,      // Mailbox Rename Domain Name (EXPERIMENTAL)
  TYPE_NULL = 10,   // NULL RR (EXPERIMENTAL)
  TYPE_WKS = 11,    // Well Known Service Description
  TYPE_PTR = 12,    // Reverse-lookup
  TYPE_HINFO = 13,  // Host Information
  TYPE_MINFO = 14,  // Mailbox or List Information
  TYPE_MX = 15,     // Mail Exchange
  TYPE_TXT = 16,    // Text Strings

  QTYPE_IXFR = 251,  // Incremental Zone Transfer
  QTYPE_AXFR = 252,  // Standard Zone Transfer
  QTYPE_MAILB = 253, // Request for Mailbox records (MB, MG, or MR)
  QTYPE_MAILA = 254, // Request for Mail Agent Records (Obsolete - see MX)
  QTYPE_ALL = 255,   // All Records
};

// RFC1035 - 3.2.4
enum EDNSQuery_RR_CLASS : uint16_t {
  CLASS_IN = 1,    // Internet, default
  CLASS_CS = 2,    // CSNET, (Obsolete - used only for examples in some obsolete RFCs)
  CLASS_CH = 3,    // CHAOS
  CLASS_HS = 4,    // Hesiod [Dyer 87]
};

// RFC1035 - 3.2.5
enum EDNSQuery_RR_QCLASS : uint16_t {
  CLASS_IN = 1,    // Internet, default
  CLASS_CS = 2,    // CSNET, (Obsolete - used only for examples in some obsolete RFCs)
  CLASS_CH = 3,    // CHAOS
  CLASS_HS = 4,    // Hesiod [Dyer 87]

  QCLASS_ALL = 255,  // Any Class
};

struct DNSQuery_RDATA {};

static std::string DNSQuery_RDATA_GetCNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetHINFO_CPU(DNSQuery_RDATA* rdata) {
  return DNSQuery_GetCharacterString((uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetHINFO_OS(DNSQuery_RDATA* rdata) {
  uint8_t* hinfo = (uint8_t*)rdata;
  uint16_t cpu_len = DNSQuery_GetCharacterStringLength(hinfo);
  return DNSQuery_GetCharacterString(hinfo + cpu_len);
}

// RFC1035 - 3.3.3 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMB_MADNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.4 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMD_MADNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.5 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMF_MADNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.6 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMG_MGMNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.7 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMINFO_RMAILBX(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetMINFO_EMAILBX(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  uint8_t* minfo = (uint8_t*)rdata;
  uint16_t cpu_len = DNSQuery_GetDomainNameCompressedSize(minfo);
  return DNSQuery_GetDomainName(h, minfo + cpu_len);
}
// -------

// RFC1035 - 3.3.8 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMR_NEWNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.9
static uint16_t DNSQuery_RDATA_GetMX_PREFERENCE(DNSQuery_RDATA* rdata) {
  return _DNS_ReadUnaligned16(rdata);
}

static std::string DNSQuery_RDATA_GetMX_EXCHANGE(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata + 2);
}
// -------

// RFC1035 - 3.3.10
template <typename T = char>
static T* DNSQuery_RDATA_GetNULL_Format(DNSQuery_RDATA* rdata, uint16_t rlen) {
  if (sizeof(T) > rlen) {
    return nullptr;
  }
  return (T*)rdata;
}

// RFC1035 - 3.3.11
static std::string DNSQuery_RDATA_GetNS_NSDNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.12
static std::string DNSQuery_RDATA_GetPTR_PTRDNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.13
static std::string DNSQuery_RDATA_GetSOA_MNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetSOA_RNAME(DNSQuery_MessageHeader* h, DNSQuery_RDATA* rdata) {
  uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
  return DNSQuery_GetDomainName(h, soainfo + mname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_SERIAL(DNSQuery_RDATA* rdata) {
  uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_REFRESH(DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 4);
}

static uint32_t DNSQuery_RDATA_GetSOA_RETRY(DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 8);
}

static uint32_t DNSQuery_RDATA_GetSOA_EXPIRE(DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 12);
}

static uint32_t DNSQuery_RDATA_GetSOA_MINIMUM(DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 16);
}
// -------

// RFC1035 - 3.3.14
static std::string DNSQuery_RDATA_GetTXT_TXTDATA(DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetCharacterString((uint8_t*)rdata);
}

static uint32_t DNSQuery_RDATA_GetA_ADDRESS(DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(rdata);
}

static uint32_t DNSQuery_RDATA_GetWKS_ADDRESS(DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(rdata);
}

static uint8_t DNSQuery_RDATA_GetWKS_PROTOCOL(DNSQuery_RDATA* rdata) {
  return ((uint8_t*)rdata)[4];
}

static bool DNSQuery_RDATA_GetWKS_BIT(DNSQuery_RDATA* rdata, uint16_t rlen, uint32_t bit) {
  if (rlen <= 5) {
    return false;
  }

  uint32_t rbit_len = (rlen - 5) * 8;
  if (bit >= rbit_len) {
    return false;
  }

  uint8_t* wks_bits = (uint8_t*)rdata + 5;
  return (bool)(wks_bits[bit >> 3] >> (7 - bit));
}

// ------------------------

enum class EDNSQuery_TransactionType {

};

enum class EDNSQuery_OperationCode {
  OPERATION_QUERY = 0,
};

enum class EDNSQuery_ReturnCode {
  RETURN_SUCCESS = 0,
  RETURN_FORMAT_ERROR = 1,
  RETURN_SERVER_FAILURE = 2,
  RETURN_NAME_ERROR = 3,
  RETURN_NOT_IMPLEMENTED = 4,
  RETURN_REFUSED = 5,
};

// RFC1035 - 4.1.1
#define FLAG_REQUEST_RESPONSE_MASK 0x8000
#define FLAG_OPERATION_CODE_MASK 0x7800
#define FLAG_AUTHORITATIVE_MASK 0x0400
#define FLAG_TRUNCATION_MASK 0x0200
#define FLAG_RECURSION_DESIRED_MASK 0x0100
#define FLAG_RECURSION_AVAILABLE_MASK 0x0080
#define FLAG_RESERVED_MASK 0x0070
#define FLAG_RETURN_CODE_MASK 0x000F

#define FLAGS_GET_RESPONSE(flags) ((bool)((flags & FLAG_REQUEST_RESPONSE_MASK) >> 15))
#define FLAGS_GET_OPERATION_CODE(flags) ((EDNSQuery_OperationCode)((flags & FLAG_OPERATION_CODE_MASK) >> 11))
#define FLAGS_GET_AUTHORITATIVE(flags) ((bool)((flags & FLAG_AUTHORITATIVE_MASK) >> 10))
#define FLAGS_GET_TRUNCATION(flags) ((bool)((flags & FLAG_TRUNCATION_MASK) >> 9))
#define FLAGS_GET_RECURSION_DESIRED(flags) ((bool)((flags & FLAG_RECURSION_DESIRED_MASK) >> 8))
#define FLAGS_GET_RECURSION_AVAILABLE(flags) ((bool)((flags & FLAG_RECURSION_AVAILABLE_MASK) >> 7))
#define FLAGS_GET_RESERVED(flags) ((flags & FLAG_RESERVED_MASK) >> 4)
#define FLAGS_GET_RETURN_CODE(flags) ((EDNSQuery_ReturnCode)((flags & FLAG_RETURN_CODE_MASK) >> 0))

struct DNSQuery_MessageHeader {
  uint16_t m_id;
  uint16_t m_flags;
  uint16_t m_qdcount;
  uint16_t m_ancount;
  uint16_t m_nscount;
  uint16_t m_arcount;
};
// ---------------------

// RFC 1035 - 4.1.2
struct DNSQuery_QuestionSection {};

static std::string DNSQuery_Question_GetQNAME(DNSQuery_MessageHeader* h, DNSQuery_QuestionSection* q) {
  return DNSQuery_GetDomainName(h, (uint8_t*)q);
}

static EDNSQuery_RR_QTYPE DNSQuery_Question_GetQTYPE(DNSQuery_MessageHeader* h, DNSQuery_QuestionSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return (EDNSQuery_RR_QTYPE)_DNS_ReadUnaligned16(qinfo + qname_len);
}

static EDNSQuery_RR_QCLASS DNSQuery_Question_GetQCLASS(DNSQuery_MessageHeader* h, DNSQuery_QuestionSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return (EDNSQuery_RR_QCLASS)_DNS_ReadUnaligned16(qinfo + qname_len + 2);
}
// ------------------

// RFC 1035 - 4.1.3
struct DNSQuery_ResourceRecordSection {};

static std::string DNSQuery_ResourceRecord_GetQNAME(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q) {
  return DNSQuery_GetDomainName(h, (uint8_t*)q);
}

static EDNSQuery_RR_TYPE DNSQuery_ResourceRecord_GetTYPE(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return (EDNSQuery_RR_TYPE)_DNS_ReadUnaligned16(qinfo + qname_len);
}

static EDNSQuery_RR_CLASS DNSQuery_ResourceRecord_GetCLASS(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (EDNSQuery_RR_CLASS)_DNS_ReadUnaligned16(qinfo + qname_len + 2);
}

static uint32_t DNSQuery_ResourceRecord_GetTTL(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return _DNS_ReadUnaligned32(qinfo + qname_len + 4);
}

static uint16_t DNSQuery_ResourceRecord_GetRDLENGTH(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return _DNS_ReadUnaligned16(qinfo + qname_len + 8);
}

static DNSQuery_RDATA* DNSQuery_ResourceRecord_GetRDATA(DNSQuery_MessageHeader* h, DNSQuery_ResourceRecordSection* q) {
  uint8_t* qinfo = (uint8_t*)q;
  uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
  return (DNSQuery_RDATA*)(qinfo + qname_len + 10);
}
// ----------------

#if 0

// Preceded by variable name field.
struct DNSQuery_QuestionEntryPartial {
  uint16_t m_question_type;
  uint16_t m_question_class;  // Normally set to 0x0001
};

#define QUESTION_GET_TYPE(value) ((EDNSQuery_QuestionType)value)

struct DNSQuery_QuestionEntry {};

static DNSQuery_QuestionEntryPartial* DNSQuery_GetQuestionEntryInfo(DNSQuery_QuestionEntry* entry) {
  uint8_t* enc_data = (uint8_t*)entry;
  while (*enc_data != '\0') {
    enc_data += *enc_data;
  }
  return (DNSQuery_QuestionEntryPartial*)(enc_data + 1);
}

static std::string DNSQuery_GetQuestionEntryName(DNSQuery_QuestionEntry* entry) {
  return DNSQuery_GetEntryName((uint8_t*)entry);
}

// Preceded by variable name field.
// Proceeded by variable resource data.
// ---
// The Resource Record Name field is encoded in the same way
// as the Question Name field unless the name is already present elsewhere
// in the DNS message, in which case a 2-byte field is used in place of a
// length-value encoded name and acts as a pointer to the name that is already present.
struct DNSQuery_ResponseMessagePartial {
  uint16_t m_resource_record_type;
  uint16_t m_resource_record_class;  // Normally set to 0x0001
  uint32_t m_ttl;
  uint16_t m_resource_data_length;
};

struct DNSQuery_ResponseMessage {};

static std::string DNSQuery_GetResponseEntryName(DNSQuery_ResponseMessage* entry) {
  return DNSQuery_GetEntryName((uint8_t*)entry);
}

static DNSQuery_MessageHeader DNSQuery_MessageHeaderCreateNameQueryRequest(uint16_t query_id, uint16_t flags, uint16_t question_entry) {
  return DNSQuery_MessageHeader{
    query_id,
    flags,
    1,
    0,
    0,
    0,
  };
}

static DNSQuery_MessageHeader DNSQuery_MessageHeaderCreateNameQueryResponse(uint16_t query_id, uint16_t flags, uint16_t question_entry) {
  return DNSQuery_MessageHeader{
    query_id,
    flags,
    1,
    0,
    0,
    0,
  };
}


struct DNSQuery_UpdateMessageHeader {
  uint16_t m_transaction_id;
  uint16_t m_flags;
  uint16_t m_zone_entry_count;
  uint16_t m_prereq_resource_count;
  uint16_t m_update_resource_count;
  uint16_t m_additional_resource_count;
  uint16_t m_zone_entry;
  //...
};

#endif
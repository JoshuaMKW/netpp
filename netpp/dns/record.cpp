// ------------------------------------
// The following code is based on
// RFC1035 and the Microsoft Docs
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <iostream>
#include <numbers>
#include "record.h"

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
// RFC1035 - 2.3.1 & 3.1
// -------------------
static std::string DNSQuery_GetDomainName(uint8_t* enc_data, uint16_t capacity) {
  uint8_t token_length = (*enc_data & 0b00111111);
  bool token_valid = true;

  // Guesstimated reservation to reduce allocations
  std::string result;
  result.reserve(capacity);

  // Build the string accordingly
  do {
    result.append((const char*)enc_data, token_length);
    enc_data += token_length;
    token_length = (*enc_data++ & 0b00111111);
    token_valid = token_length > 0;
    if (token_valid) {
      result.append(".");
    }
  } while (token_valid && result.length() < capacity);

  return result;
}

static uint16_t DNSQuery_GetDomainNameLength(uint8_t* enc_data, uint16_t capacity) {
  uint16_t length = 0;

  uint8_t* enc_data_end = (uint8_t*)enc_data;
  while (*enc_data_end != '\0') {
    enc_data_end += *enc_data_end;
    if (enc_data_end - enc_data > capacity) {
      return capacity;
    }
  }
  return (enc_data_end - enc_data) + 1;
}

static std::string DNSQuery_GetCharacterString(uint8_t* enc_data, uint16_t capacity) {
  uint8_t token_length = (*enc_data & 0b11111111);

  // Guesstimated reservation to reduce allocations
  std::string result((const char*)(enc_data + 1),
    std::min<uint16_t>(token_length, capacity));

  return result;
}

static uint16_t DNSQuery_GetCharacterStringLength(uint8_t* enc_data, uint16_t capacity) {
  uint16_t length = *enc_data;
  return std::min<uint16_t>(length + 1, capacity);
}
// -----------------

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
  QCLASS_ALL = 255,  // Any Class
};

// ------------------------
// RFC1035 - 3.2.1
// ------------------------
struct DNSQuery_RRPartial {
  EDNSQuery_RR_TYPE m_type;
  EDNSQuery_RR_CLASS m_class;
  uint32_t m_ttl;
  uint16_t m_rdlength;
};

struct DNSQuery_RR {};

struct DNSQuery_RDATA {};

static DNSQuery_RRPartial* DNSQuery_RR_GetPartial(DNSQuery_RR* rr) {
  return (DNSQuery_RRPartial*)
    ((uint8_t*)rr + DNSQuery_GetDomainNameLength((uint8_t*)rr, 256));
}

static std::string DNSQuery_RR_GetNAME(DNSQuery_RR* rr) {
  return DNSQuery_GetDomainName((uint8_t*)rr, 256);
}

static DNSQuery_RDATA* DNSQuery_RR_GetRDATA(DNSQuery_RR* rr) {
  return (DNSQuery_RDATA*)((uint8_t*)DNSQuery_RR_GetPartial(rr) + 10);
}

static std::string DNSQuery_RDATA_GetCNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

static std::string DNSQuery_RDATA_GetHINFO_CPU(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetCharacterString((uint8_t*)rdata, rlen);
}

static std::string DNSQuery_RDATA_GetHINFO_OS(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* hinfo = (uint8_t*)rdata;
  uint16_t cpu_len = DNSQuery_GetCharacterStringLength(hinfo, rlen);
  return DNSQuery_GetCharacterString(hinfo + cpu_len, rlen - cpu_len);
}

// RFC1035 - 3.3.3 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMB_MADNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.4 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMD_MADNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.5 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMF_MADNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.6 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMG_MGMNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.7 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMINFO_RMAILBX(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

static std::string DNSQuery_RDATA_GetMINFO_EMAILBX(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* minfo = (uint8_t*)rdata;
  uint16_t cpu_len = DNSQuery_GetDomainNameLength(minfo, rlen);
  return DNSQuery_GetDomainName(minfo + cpu_len, rlen - cpu_len);
}
// -------

// RFC1035 - 3.3.8 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMR_NEWNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.9
static uint16_t DNSQuery_RDATA_GetMX_PREFERENCE(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return *(uint16_t*)rdata;
}

static std::string DNSQuery_RDATA_GetMX_EXCHANGE(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata + 2, rlen - 2);
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
static std::string DNSQuery_RDATA_GetNS_NSDNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.12
static std::string DNSQuery_RDATA_GetPTR_PTRDNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

// RFC1035 - 3.3.13
static std::string DNSQuery_RDATA_GetSOA_MNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetDomainName((uint8_t*)rdata, rlen);
}

static std::string DNSQuery_RDATA_GetSOA_RNAME(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  return DNSQuery_GetDomainName(soainfo + mname_len, rlen - mname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_SERIAL(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  uint16_t rname_len = DNSQuery_GetDomainNameLength(soainfo + mname_len, rlen - mname_len);
  return *(uint32_t*)(soainfo + mname_len + rname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_REFRESH(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  uint16_t rname_len = DNSQuery_GetDomainNameLength(soainfo + mname_len, rlen - mname_len);
  return *(uint32_t*)(soainfo + mname_len + rname_len + 4);
}

static uint32_t DNSQuery_RDATA_GetSOA_RETRY(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  uint16_t rname_len = DNSQuery_GetDomainNameLength(soainfo + mname_len, rlen - mname_len);
  return *(uint32_t*)(soainfo + mname_len + rname_len + 8);
}

static uint32_t DNSQuery_RDATA_GetSOA_EXPIRE(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  uint16_t rname_len = DNSQuery_GetDomainNameLength(soainfo + mname_len, rlen - mname_len);
  return *(uint32_t*)(soainfo + mname_len + rname_len + 12);
}

static uint32_t DNSQuery_RDATA_GetSOA_MINIMUM(DNSQuery_RDATA* rdata, uint16_t rlen) {
  uint8_t* soainfo = (uint8_t*)rdata;
  uint16_t mname_len = DNSQuery_GetDomainNameLength(soainfo, rlen);
  uint16_t rname_len = DNSQuery_GetDomainNameLength(soainfo + mname_len, rlen - mname_len);
  return *(uint32_t*)(soainfo + mname_len + rname_len + 16);
}
// -------

// RFC1035 - 3.3.14
static std::string DNSQuery_RDATA_GetTXT_TXTDATA(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return DNSQuery_GetCharacterString((uint8_t*)rdata, rlen);
}

static uint32_t DNSQuery_RDATA_GetA_ADDRESS(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return *(uint32_t*)rdata;
}

static uint32_t DNSQuery_RDATA_GetWKS_ADDRESS(DNSQuery_RDATA* rdata, uint16_t rlen) {
  return *(uint32_t*)rdata;
}

static uint8_t DNSQuery_RDATA_GetWKS_PROTOCOL(DNSQuery_RDATA* rdata, uint16_t rlen) {
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

struct DNSQuery_MessageHeader {
  uint16_t m_transaction_id;
  uint16_t m_flags;
  uint16_t m_question_resource_record_count;
  uint16_t m_answer_resource_record_count;
  uint16_t m_authority_resource_record_count;
  uint16_t m_additional_resource_record_count;
};

enum class EDNSQuery_TransactionType {

};

enum class EDNSQuery_OperationCode {
  OPERATION_QUERY = 0,
};

enum class EDNSQuery_ReturnCode {
  RETURN_SUCCESS = 0,
  RETURN_NAME_ERROR = 3,
};

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
#define FLAGS_GET_RESERVED(flags) (flags & FLAG_RESERVED_MASK) >> 4)
#define FLAGS_GET_RETURN_CODE(flags) ((EDNSQuery_ReturnCode)((flags & FLAG_RETURN_CODE_MASK) >> 0))

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
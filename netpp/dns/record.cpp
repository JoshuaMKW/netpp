// ------------------------------------
// The following code is based on
// RFC1035 and the Microsoft Docs
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <iostream>
#include <numbers>
#include <string>
#include <type_traits>

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

template <typename T, typename U>
auto _DNS_OffsetPtr(U* ptr, uint32_t ofs) -> std::conditional_t<std::is_const_v<U>, const T*, T*>
{
    // If U is const, byte_ptr will be const uint8_t*. Otherwise, uint8_t*.
    using byte_t = std::conditional_t<std::is_const_v<U>, const uint8_t, uint8_t>;

    if (!ptr)
        return nullptr;

    byte_t* byte_ptr = reinterpret_cast<byte_t*>(ptr);
    return byte_ptr + ofs;
}

static uint16_t _DNS_ReadUnaligned16(const void* ptr)
{
    uint16_t val;
    std::memcpy(&val, ptr, sizeof(uint16_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

static uint32_t _DNS_ReadUnaligned32(const void* ptr)
{
    uint32_t val;
    std::memcpy(&val, ptr, sizeof(uint32_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

static void _DNS_WriteUnaligned16(void* ptr, uint16_t val)
{
    uint16_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint16_t));
}

static void _DNS_WriteUnaligned32(void* ptr, uint32_t val)
{
    uint32_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint32_t));
}

// ------------------------------------
// See: RFC1035 - 2.3.3.
// ------------------------------------
static int DNS_StringCompareInsensitive(const std::string& l, const std::string& r)
{
    int difference = 0;

    size_t boundary = std::min(l.size(), r.size());
    for (size_t i = 0; i < boundary; ++i) {
        int li = ::tolower((int)l[i]);
        int ri = ::tolower((int)r[i]);
        difference += li - ri;
    }

    if (difference == 0) {
        return (int)(l.size() - r.size());
    }
    return difference;

} //-------------------
// RFC1035 - 2.3.1 & 3.1 & 4.1.4
// -------------------
static std::string DNSQuery_GetDomainName(const DNSQuery_MessageHeader* h, const uint8_t* enc_data)
{
    std::string result;
    result.reserve(DNS_NAME_OCTET_LIMIT);

    int32_t pointers_chased = 0;

    while (result.length() < DNS_NAME_OCTET_LIMIT) {
        const bool is_compressed = (enc_data[0] & 0b11000000) == 0b11000000;
        uint8_t token_length = (enc_data[0] & 0b00111111);

        if (is_compressed) {
            if (pointers_chased >= 10) {
                break; // We exit early to avoid malicious attacks
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

static uint8_t DNSQuery_GetDomainNameCompressedSize(const uint8_t* enc_data)
{
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

static uint8_t DNSQuery_GetDomainNameLength(const DNSQuery_MessageHeader* h, const uint8_t* enc_data)
{
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

static std::string DNSQuery_GetCharacterString(const uint8_t* enc_data)
{
    const uint8_t token_length = (*enc_data & 0b11111111); // Is already <= DNS_NAME_OCTET_LIMIT due to the 1 byte length prefix
    return std::string((const char*)(enc_data + 1), token_length);
}

static uint16_t DNSQuery_GetCharacterStringLength(const uint8_t* enc_data)
{
    return (uint16_t)(*enc_data) + 1;
}
// -----------------

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

#if 0
struct DNSQuery_MessageHeader {
  uint16_t m_id;
  uint16_t m_flags;
  uint16_t m_qdcount;
  uint16_t m_ancount;
  uint16_t m_nscount;
  uint16_t m_arcount;
};
#else
struct DNSQuery_MessageHeader { };

static uint16_t DNSQuery_MessageHeader_GetDataSize(const DNSQuery_MessageHeader* h) { return 12; }

static uint16_t DNSQuery_MessageHeader_GetID(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(h);
}

static uint16_t DNSQuery_MessageHeader_GetFlags(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 2));
}

static uint16_t DNSQuery_MessageHeader_GetQDCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 4));
}

static uint16_t DNSQuery_MessageHeader_GetANCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 6));
}

static uint16_t DNSQuery_MessageHeader_GetNSCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 8));
}

static uint16_t DNSQuery_MessageHeader_GetARCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 10));
}
#endif

struct DNSQuery_RDATA { };

static std::string DNSQuery_RDATA_GetCNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetHINFO_CPU(const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetCharacterString((uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetHINFO_OS(const DNSQuery_RDATA* rdata)
{
    uint8_t* hinfo = (uint8_t*)rdata;
    uint16_t cpu_len = DNSQuery_GetCharacterStringLength(hinfo);
    return DNSQuery_GetCharacterString(hinfo + cpu_len);
}

// RFC1035 - 3.3.3 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMB_MADNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)rdata);
}

// RFC1035 - 3.3.4 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMD_MADNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)rdata);
}

// RFC1035 - 3.3.5 (OBSOLETE)
static std::string DNSQuery_RDATA_GetMF_MADNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)rdata);
}

// RFC1035 - 3.3.6 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMG_MGMNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)rdata);
}

// RFC1035 - 3.3.7 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMINFO_RMAILBX(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetMINFO_EMAILBX(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    const uint8_t* minfo = (const uint8_t*)rdata;
    uint16_t cpu_len = DNSQuery_GetDomainNameCompressedSize(minfo);
    return DNSQuery_GetDomainName(h, minfo + cpu_len);
}
// -------

// RFC1035 - 3.3.8 (EXPERIMENTAL)
static std::string DNSQuery_RDATA_GetMR_NEWNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.9
static uint16_t DNSQuery_RDATA_GetMX_PREFERENCE(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(rdata);
}

static std::string DNSQuery_RDATA_GetMX_EXCHANGE(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata + 2);
}
// -------

// RFC1035 - 3.3.10
template <typename T = char>
static T* DNSQuery_RDATA_GetNULL_Format(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    if (sizeof(T) > rdlength) {
        return nullptr;
    }
    return (T*)rdata;
}

// RFC1035 - 3.3.11
static std::string DNSQuery_RDATA_GetNS_NSDNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.12
static std::string DNSQuery_RDATA_GetPTR_PTRDNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

// RFC1035 - 3.3.13
static std::string DNSQuery_RDATA_GetSOA_MNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(h, (uint8_t*)rdata);
}

static std::string DNSQuery_RDATA_GetSOA_RNAME(const DNSQuery_MessageHeader* h, const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    return DNSQuery_GetDomainName(h, soainfo + mname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_SERIAL(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len);
}

static uint32_t DNSQuery_RDATA_GetSOA_REFRESH(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 4);
}

static uint32_t DNSQuery_RDATA_GetSOA_RETRY(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 8);
}

static uint32_t DNSQuery_RDATA_GetSOA_EXPIRE(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 12);
}

static uint32_t DNSQuery_RDATA_GetSOA_MINIMUM(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 16);
}
// -------

// RFC1035 - 3.3.14
static std::vector<std::string> DNSQuery_RDATA_GetTXT_TXTDATA(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    std::vector<std::string> result;

    const uint8_t* strptr = (const uint8_t*)rdata;
    uint32_t marker = 0;
    do {
        result.emplace_back(std::move(DNSQuery_GetCharacterString(strptr + marker)));
        marker += DNSQuery_GetCharacterStringLength(strptr + marker);
    } while (marker < rdlength);
    
    return result;
}

static uint32_t DNSQuery_RDATA_GetA_ADDRESS(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(rdata);
}

static uint32_t DNSQuery_RDATA_GetWKS_ADDRESS(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(rdata);
}

static uint8_t DNSQuery_RDATA_GetWKS_PROTOCOL(const DNSQuery_RDATA* rdata)
{
    return ((uint8_t*)rdata)[4];
}

static std::vector<uint8_t> DNSQuery_RDATA_GetWKS_BITMAP(const DNSQuery_RDATA* rdata, uint16_t rdlength) {

    uint8_t* wks_bits = (uint8_t*)rdata + 5;
    return std::vector(wks_bits, wks_bits + (rdlength - 5));
}

static bool DNSQuery_RDATA_GetWKS_BIT(const DNSQuery_RDATA* rdata, uint16_t rlen, uint32_t bit)
{
    if (rlen <= 5) {
        return false;
    }

    uint32_t rbit_len = (rlen - 5) * 8;
    if (bit >= rbit_len) {
        return false;
    }

    uint8_t* wks_bits = (uint8_t*)rdata + 5;
    return (bool)(wks_bits[bit >> 3] >> (7 - (bit % 8)));
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

// ---------------------

// RFC 1035 - 4.1.2
struct DNSQuery_QuestionSection { };

static uint16_t DNSQuery_Question_GetDataSize(const DNSQuery_MessageHeader* h, const DNSQuery_QuestionSection* q)
{
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize((uint8_t*)q);
    return qname_len + 4;
}

static std::string DNSQuery_Question_GetQNAME(const DNSQuery_MessageHeader* h, const DNSQuery_QuestionSection* q)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)q);
}

static netpp::EDNSQuery_RR_QTYPE DNSQuery_Question_GetQTYPE(const DNSQuery_MessageHeader* h, const DNSQuery_QuestionSection* q)
{
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize((uint8_t*)q);
    return (netpp::EDNSQuery_RR_QTYPE)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(q, qname_len));
}

static netpp::EDNSQuery_RR_QCLASS DNSQuery_Question_GetQCLASS(const DNSQuery_MessageHeader* h, const DNSQuery_QuestionSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (netpp::EDNSQuery_RR_QCLASS)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2));
}
// ------------------

// RFC 1035 - 4.1.3
struct DNSQuery_ResourceRecordSection { };

static uint16_t DNSQuery_ResourceRecord_GetDataSize(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize((uint8_t*)q);
    return qname_len + 1 + DNSQuery_ResourceRecord_GetRDLENGTH(h, q);
}

static std::string DNSQuery_ResourceRecord_GetQNAME(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    return DNSQuery_GetDomainName(h, (const uint8_t*)q);
}

static netpp::EDNSQuery_RR_TYPE DNSQuery_ResourceRecord_GetTYPE(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (netpp::EDNSQuery_RR_TYPE)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len));
}

static netpp::EDNSQuery_RR_CLASS DNSQuery_ResourceRecord_GetCLASS(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (netpp::EDNSQuery_RR_CLASS)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2));
}

static uint32_t DNSQuery_ResourceRecord_GetTTL(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return _DNS_ReadUnaligned32(_DNS_OffsetPtr<void>(qinfo, qname_len + 4));
}

static uint16_t DNSQuery_ResourceRecord_GetRDLENGTH(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 8));
}

static DNSQuery_RDATA* DNSQuery_ResourceRecord_GetRDATA(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (DNSQuery_RDATA*)(_DNS_OffsetPtr<void>(qinfo, qname_len + 10));
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

namespace netpp {

static DNS_RData* ParseRData(const DNSQuery_MessageHeader* header, EDNSQuery_RR_TYPE type, EDNSQuery_RR_CLASS klass, uint32_t rdlength, const DNSQuery_RDATA* rdata)
{
    switch (type) {
    default:
        return nullptr;
    case TYPE_A: {
        const uint32_t address = DNSQuery_RDATA_GetA_ADDRESS(rdata);
        return new DNS_RData_A(address);
    }
    case TYPE_CNAME: {
        const std::string cname = DNSQuery_RDATA_GetCNAME(header, rdata);
        return new DNS_RData_CNAME(cname);
    }
    case TYPE_HINFO: {
        const std::string cpu = DNSQuery_RDATA_GetHINFO_CPU(rdata);
        const std::string os = DNSQuery_RDATA_GetHINFO_OS(rdata);
        return new DNS_RData_HINFO(cpu, os);
    }
    case TYPE_MB: {
        const std::string madname = DNSQuery_RDATA_GetMB_MADNAME(header, rdata);
        return new DNS_RData_MB(madname);
    }
    case TYPE_MD: {
        const std::string madname = DNSQuery_RDATA_GetMD_MADNAME(header, rdata);
        return new DNS_RData_MD(madname);
    }
    case TYPE_MF: {
        const std::string madname = DNSQuery_RDATA_GetMF_MADNAME(header, rdata);
        return new DNS_RData_MF(madname);
    }
    case TYPE_MG: {
        const std::string mgmname = DNSQuery_RDATA_GetMG_MGMNAME(header, rdata);
        return new DNS_RData_MG(mgmname);
    }
    case TYPE_MINFO: {
        const std::string rmailbx = DNSQuery_RDATA_GetMINFO_RMAILBX(header, rdata);
        const std::string emailbx = DNSQuery_RDATA_GetMINFO_EMAILBX(header, rdata);
        return new DNS_RData_MINFO(rmailbx, emailbx);
    }
    case TYPE_MR: {
        const std::string newname = DNSQuery_RDATA_GetMR_NEWNAME(header, rdata);
        return new DNS_RData_MR(newname);
    }
    case TYPE_MX: {
        const uint16_t preference = DNSQuery_RDATA_GetMX_PREFERENCE(rdata);
        const std::string exchange = DNSQuery_RDATA_GetMX_EXCHANGE(header, rdata);
        return new DNS_RData_MX(preference, exchange);
    }
    case TYPE_NULL: {
        const uint8_t *anything = DNSQuery_RDATA_GetNULL_Format<uint8_t>(rdata, rdlength);
        return new DNS_RData_NULL(std::vector<uint8_t>(anything, anything + rdlength));
    }
    case TYPE_NS: {
        const std::string nsdname = DNSQuery_RDATA_GetNS_NSDNAME(header, rdata);
        return new DNS_RData_NS(nsdname);
    }
    case TYPE_PTR: {
        const std::string nsdname = DNSQuery_RDATA_GetPTR_PTRDNAME(header, rdata);
        return new DNS_RData_PTR(nsdname);
    }
    case TYPE_SOA: {
        const std::string mname = DNSQuery_RDATA_GetSOA_MNAME(header, rdata);
        const std::string rname = DNSQuery_RDATA_GetSOA_RNAME(header, rdata);
        const uint32_t serial = DNSQuery_RDATA_GetSOA_SERIAL(rdata);
        const uint32_t refresh = DNSQuery_RDATA_GetSOA_REFRESH(rdata);
        const uint32_t retry = DNSQuery_RDATA_GetSOA_RETRY(rdata);
        const uint32_t expire = DNSQuery_RDATA_GetSOA_EXPIRE(rdata);
        const uint32_t minimum = DNSQuery_RDATA_GetSOA_MINIMUM(rdata);
        return new DNS_RData_SOA(mname, rname, serial, refresh, retry, expire, minimum);
    }
    case TYPE_TXT: {
        const std::vector<std::string> txtdata = DNSQuery_RDATA_GetTXT_TXTDATA(rdata, rdlength);
        return new DNS_RData_TXT(txtdata);
    }
    case TYPE_WKS: {
        const uint32_t address = DNSQuery_RDATA_GetWKS_ADDRESS(rdata);
        const uint8_t protocol = DNSQuery_RDATA_GetWKS_PROTOCOL(rdata);
        const std::vector<uint8_t> bitmap = DNSQuery_RDATA_GetWKS_BITMAP(rdata, rdlength);
        return new DNS_RData_WKS(address, protocol, bitmap);
    }
    }
}

DNS_Question::DNS_Question(const std::string& name, EDNSQuery_RR_QTYPE type, EDNSQuery_RR_QCLASS klass)
{
    m_name = name;
    m_type = type;
    m_class = klass;
}

bool DNS_Message::is_data_query(const char* msg_buf, uint32_t buf_size)
{
    if (!msg_buf || buf_size == 0) {
        return false;
    }

    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)msg_buf;
    return !FLAGS_GET_RESPONSE(
        DNSQuery_MessageHeader_GetFlags(header));
}

bool DNS_Message::is_data_response(const char* msg_buf, uint32_t buf_size)
{
    if (!msg_buf || buf_size == 0) {
        return false;
    }

    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)msg_buf;
    return FLAGS_GET_RESPONSE(
        DNSQuery_MessageHeader_GetFlags(header));
}

DNS_Message* DNS_Message::create_query()
{
    return nullptr;
}

DNS_Message* DNS_Message::create_response()
{
    return nullptr;
}

DNS_Message* DNS_Message::create(const char* dns_buf, int buflen)
{
    if (!dns_buf || buflen == 0) {
        return nullptr;
    }

    DNS_Message* result = new DNS_Message;

    const void* next_section = nullptr; // Used for incrementing pointers

    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)dns_buf;

    const uint16_t message_id = DNSQuery_MessageHeader_GetID(header);
    const uint16_t message_flags = DNSQuery_MessageHeader_GetFlags(header);
    const uint16_t message_qdcount = DNSQuery_MessageHeader_GetQDCount(header);
    const uint16_t message_ancount = DNSQuery_MessageHeader_GetANCount(header);
    const uint16_t message_nscount = DNSQuery_MessageHeader_GetNSCount(header);
    const uint16_t message_arcount = DNSQuery_MessageHeader_GetARCount(header);

    next_section = _DNS_OffsetPtr<void>(header, DNSQuery_MessageHeader_GetDataSize(header));

    const DNSQuery_QuestionSection* question = nullptr;

    // Process question entries
    for (uint16_t i = 0; i < message_qdcount; ++i) {
        const DNSQuery_QuestionSection* question = static_cast<const DNSQuery_QuestionSection*>(next_section);

        const std::string question_name = DNSQuery_Question_GetQNAME(header, question);
        const EDNSQuery_RR_QTYPE question_type = DNSQuery_Question_GetQTYPE(header, question);
        const EDNSQuery_RR_QCLASS question_class = DNSQuery_Question_GetQCLASS(header, question);

        result->m_questions.emplace_back(question_name, question_type, question_class);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_Question_GetDataSize(header, question));
    }

    // Process answer entries
    for (uint16_t i = 0; i < message_ancount; ++i) {
        const DNSQuery_ResourceRecordSection* answer = static_cast<const DNSQuery_ResourceRecordSection*>(next_section);

        const std::string answer_name = DNSQuery_ResourceRecord_GetQNAME(header, answer);
        const EDNSQuery_RR_TYPE answer_type = DNSQuery_ResourceRecord_GetTYPE(header, answer);
        const EDNSQuery_RR_CLASS answer_class = DNSQuery_ResourceRecord_GetCLASS(header, answer);
        const uint32_t answer_ttl = DNSQuery_ResourceRecord_GetTTL(header, answer);
        const uint32_t answer_rdlength = DNSQuery_ResourceRecord_GetRDLENGTH(header, answer);

        const DNSQuery_RDATA* answer_low_rdata = DNSQuery_ResourceRecord_GetRDATA(header, answer);
        const DNS_RData* answer_rdata = ParseRData(header, answer_type, answer_class, answer_rdlength, answer_low_rdata);

        result->m_answers.emplace_back(answer_name, answer_type, answer_class, answer_ttl, answer_rdata);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_ResourceRecord_GetDataSize(header, answer));
    }

    // Process authoritative entries
    for (uint16_t i = 0; i < message_ancount; ++i) {
        const DNSQuery_ResourceRecordSection* authoritative = static_cast<const DNSQuery_ResourceRecordSection*>(next_section);

        const std::string authoritative_name = DNSQuery_ResourceRecord_GetQNAME(header, authoritative);
        const EDNSQuery_RR_TYPE authoritative_type = DNSQuery_ResourceRecord_GetTYPE(header, authoritative);
        const EDNSQuery_RR_CLASS authoritative_class = DNSQuery_ResourceRecord_GetCLASS(header, authoritative);
        const uint32_t authoritative_ttl = DNSQuery_ResourceRecord_GetTTL(header, authoritative);
        const uint32_t authoritative_rdlength = DNSQuery_ResourceRecord_GetRDLENGTH(header, authoritative);

        const DNSQuery_RDATA* authoritative_low_rdata = DNSQuery_ResourceRecord_GetRDATA(header, authoritative);
        const DNS_RData* authoritative_rdata = ParseRData(header, authoritative_type, authoritative_class, authoritative_rdlength, authoritative_low_rdata);

        result->m_authoritatives.emplace_back(authoritative_name, authoritative_type, authoritative_class, authoritative_ttl, authoritative_rdata);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_ResourceRecord_GetDataSize(header, authoritative));
    }

    // Process additional entries
    for (uint16_t i = 0; i < message_ancount; ++i) {
        const DNSQuery_ResourceRecordSection* additional = static_cast<const DNSQuery_ResourceRecordSection*>(next_section);

        const std::string additional_name = DNSQuery_ResourceRecord_GetQNAME(header, additional);
        const EDNSQuery_RR_TYPE additional_type = DNSQuery_ResourceRecord_GetTYPE(header, additional);
        const EDNSQuery_RR_CLASS additional_class = DNSQuery_ResourceRecord_GetCLASS(header, additional);
        const uint32_t additional_ttl = DNSQuery_ResourceRecord_GetTTL(header, additional);
        const uint32_t additional_rdlength = DNSQuery_ResourceRecord_GetRDLENGTH(header, additional);

        const DNSQuery_RDATA* additional_low_rdata = DNSQuery_ResourceRecord_GetRDATA(header, additional);
        const DNS_RData* additional_rdata = ParseRData(header, additional_type, additional_class, additional_rdlength, additional_low_rdata);

        result->m_additionals.emplace_back(additional_name, additional_type, additional_class, additional_ttl, additional_rdata);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_ResourceRecord_GetDataSize(header, additional));
    }

    return result;
}

const char* DNS_Message::build_buf(const DNS_Message& msg, uint32_t* size_out)
{
    return nullptr;
}

}

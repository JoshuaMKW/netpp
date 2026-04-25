// ------------------------------------
// The following code is based on
// RFC1035 and the Microsoft Docs
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <iostream>
#include <string>
#include <type_traits>

#include "netpp/netpp.h"
#include "netpp/dns/record.h"
#include "netpp/protocol.h"
#include "netpp/socket.h"

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

}

struct DNSQuery_MessageHeader { };

//---------------------------------
// RFC1035 - 2.3.1 & 3.1 & 4.1.4
// --------------------------------
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

static uint16_t DNSQuery_MessageHeader_GetDataSize(const DNSQuery_MessageHeader* h) { return 12; }

static uint16_t DNSQuery_MessageHeader_GetID(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(h);
}

static void DNSQuery_MessageHeader_SetID(DNSQuery_MessageHeader* h, uint16_t id) {
    _DNS_WriteUnaligned16(h, id);
}

static uint16_t DNSQuery_MessageHeader_GetFlags(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 2));
}

static void DNSQuery_MessageHeader_SetFlags(DNSQuery_MessageHeader* h, uint16_t flags)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(h, 2), flags);
}

static uint16_t DNSQuery_MessageHeader_GetQDCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 4));
}

static void DNSQuery_MessageHeader_SetQDCount(DNSQuery_MessageHeader* h, uint16_t qdcount)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(h, 4), qdcount);
}

static uint16_t DNSQuery_MessageHeader_GetANCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 6));
}

static void DNSQuery_MessageHeader_SetANCount(DNSQuery_MessageHeader* h, uint16_t ancount)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(h, 6), ancount);
}

static uint16_t DNSQuery_MessageHeader_GetNSCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 8));
}

static void DNSQuery_MessageHeader_SetNSCount(DNSQuery_MessageHeader* h, uint16_t nscount)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(h, 8), nscount);
}

static uint16_t DNSQuery_MessageHeader_GetARCount(const DNSQuery_MessageHeader* h)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(h, 10));
}

static void DNSQuery_MessageHeader_SetARCount(DNSQuery_MessageHeader* h, uint16_t arcount)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(h, 10), arcount);
}

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

static void DNSQuery_RDATA_SetMX_PREFERENCE(DNSQuery_RDATA* rdata, uint16_t preference)
{
    _DNS_WriteUnaligned16(rdata, preference);
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

static void DNSQuery_RDATA_SetSOA_SERIAL(DNSQuery_RDATA* rdata, uint32_t serial)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    _DNS_WriteUnaligned32(soainfo + mname_len + rname_len, serial);
}

static uint32_t DNSQuery_RDATA_GetSOA_REFRESH(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 4);
}

static void DNSQuery_RDATA_SetSOA_REFRESH(DNSQuery_RDATA* rdata, uint32_t refresh)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    _DNS_WriteUnaligned32(soainfo + mname_len + rname_len + 4, refresh);
}

static uint32_t DNSQuery_RDATA_GetSOA_RETRY(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 8);
}

static void DNSQuery_RDATA_SetSOA_RETRY(DNSQuery_RDATA* rdata, uint32_t retry)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    _DNS_WriteUnaligned32(soainfo + mname_len + rname_len + 8, retry);
}

static uint32_t DNSQuery_RDATA_GetSOA_EXPIRE(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 12);
}

static void DNSQuery_RDATA_SetSOA_EXPIRE(DNSQuery_RDATA* rdata, uint32_t expire)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    _DNS_WriteUnaligned32(soainfo + mname_len + rname_len + 12, expire);
}

static uint32_t DNSQuery_RDATA_GetSOA_MINIMUM(const DNSQuery_RDATA* rdata)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    return _DNS_ReadUnaligned32(soainfo + mname_len + rname_len + 16);
}

static void DNSQuery_RDATA_SetSOA_MINIMUM(DNSQuery_RDATA* rdata, uint32_t minimum)
{
    uint8_t* soainfo = (uint8_t*)rdata;
    uint16_t mname_len = DNSQuery_GetDomainNameCompressedSize(soainfo);
    uint16_t rname_len = DNSQuery_GetDomainNameCompressedSize(soainfo + mname_len);
    _DNS_WriteUnaligned32(soainfo + mname_len + rname_len + 16, minimum);
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

static void DNSQuery_RDATA_SetA_ADDRESS(DNSQuery_RDATA* rdata, uint32_t address)
{
    _DNS_WriteUnaligned32(rdata, address);
}

static uint32_t DNSQuery_RDATA_GetWKS_ADDRESS(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(rdata);
}

static void DNSQuery_RDATA_SetWKS_ADDRESS(DNSQuery_RDATA* rdata, uint32_t address)
{
    _DNS_WriteUnaligned32(rdata, address);
}

static uint8_t DNSQuery_RDATA_GetWKS_PROTOCOL(const DNSQuery_RDATA* rdata)
{
    return ((uint8_t*)rdata)[4];
}

static void DNSQuery_RDATA_SetWKS_PROTOCOL(DNSQuery_RDATA* rdata, uint8_t protocol)
{
    ((uint8_t*)rdata)[4] = protocol;
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

static void DNSQuery_RDATA_SetWKS_BIT(DNSQuery_RDATA* rdata, uint16_t rlen, uint32_t bit, bool value)
{
    if (rlen <= 5) {
        return;
    }

    uint32_t rbit_len = (rlen - 5) * 8;
    if (bit >= rbit_len) {
        return;
    }

    uint8_t* wks_bits = (uint8_t*)rdata + 5;
    uint32_t byte_index = bit >> 3;
    uint8_t bit_mask = 1 << (7 - (bit % 8));

    if (value) {
        wks_bits[byte_index] |= bit_mask;
    } else {
        wks_bits[byte_index] &= ~bit_mask;
    }
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

static void DNSQuery_Question_SetQTYPE(DNSQuery_QuestionSection* q, netpp::EDNSQuery_RR_QTYPE type)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len), (uint16_t)type);
}

static netpp::EDNSQuery_RR_QCLASS DNSQuery_Question_GetQCLASS(const DNSQuery_MessageHeader* h, const DNSQuery_QuestionSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (netpp::EDNSQuery_RR_QCLASS)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2));
}

static void DNSQuery_Question_SetQCLASS(DNSQuery_QuestionSection* q, netpp::EDNSQuery_RR_QCLASS klass)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2), (uint16_t)klass);
}

// ------------------

// RFC 1035 - 4.1.3
struct DNSQuery_ResourceRecordSection { };

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

static void DNSQuery_ResourceRecord_SetTYPE(DNSQuery_ResourceRecordSection* q, netpp::EDNSQuery_RR_TYPE type)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len), (uint16_t)type);
}

static netpp::EDNSQuery_RR_CLASS DNSQuery_ResourceRecord_GetCLASS(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (netpp::EDNSQuery_RR_CLASS)_DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2));
}

static void DNSQuery_ResourceRecord_SetCLASS(DNSQuery_ResourceRecordSection* q, netpp::EDNSQuery_RR_CLASS klass)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 2), (uint16_t)klass);
}

static uint32_t DNSQuery_ResourceRecord_GetTTL(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return _DNS_ReadUnaligned32(_DNS_OffsetPtr<void>(qinfo, qname_len + 4));
}

static void DNSQuery_ResourceRecord_SetTTL(DNSQuery_ResourceRecordSection* q, uint32_t ttl)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned32(_DNS_OffsetPtr<void>(qinfo, qname_len + 4), ttl);
}

static uint16_t DNSQuery_ResourceRecord_GetRDLENGTH(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 8));
}

static void DNSQuery_ResourceRecord_SetRDLENGTH(DNSQuery_ResourceRecordSection* q, uint16_t rdlength)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(qinfo, qname_len + 8), rdlength);
}

static DNSQuery_RDATA* DNSQuery_ResourceRecord_GetRDATA(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint8_t* qinfo = (uint8_t*)q;
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize(qinfo);
    return (DNSQuery_RDATA*)(_DNS_OffsetPtr<void>(qinfo, qname_len + 10));
}

static uint16_t DNSQuery_ResourceRecord_GetDataSize(const DNSQuery_MessageHeader* h, const DNSQuery_ResourceRecordSection* q)
{
    uint16_t qname_len = DNSQuery_GetDomainNameCompressedSize((uint8_t*)q);
    return qname_len + 10 + DNSQuery_ResourceRecord_GetRDLENGTH(h, q);
}

// ----------------

namespace netpp {

static DNS_RData* ParseRData(const DNSQuery_MessageHeader* header, EDNSQuery_RR_TYPE type, EDNSQuery_RR_CLASS klass, uint32_t rdlength, const DNSQuery_RDATA* rdata)
{
    switch (type) {
    default:
        return nullptr;
    case EDNSQuery_RR_TYPE::TYPE_A: {
        const uint32_t address = DNSQuery_RDATA_GetA_ADDRESS(rdata);
        return new DNS_RData_A(address);
    }
    case EDNSQuery_RR_TYPE::TYPE_CNAME: {
        const std::string cname = DNSQuery_RDATA_GetCNAME(header, rdata);
        return new DNS_RData_CNAME(cname);
    }
    case EDNSQuery_RR_TYPE::TYPE_HINFO: {
        const std::string cpu = DNSQuery_RDATA_GetHINFO_CPU(rdata);
        const std::string os = DNSQuery_RDATA_GetHINFO_OS(rdata);
        return new DNS_RData_HINFO(cpu, os);
    }
    case EDNSQuery_RR_TYPE::TYPE_MB: {
        const std::string madname = DNSQuery_RDATA_GetMB_MADNAME(header, rdata);
        return new DNS_RData_MB(madname);
    }
    case EDNSQuery_RR_TYPE::TYPE_MD: {
        const std::string madname = DNSQuery_RDATA_GetMD_MADNAME(header, rdata);
        return new DNS_RData_MD(madname);
    }
    case EDNSQuery_RR_TYPE::TYPE_MF: {
        const std::string madname = DNSQuery_RDATA_GetMF_MADNAME(header, rdata);
        return new DNS_RData_MF(madname);
    }
    case EDNSQuery_RR_TYPE::TYPE_MG: {
        const std::string mgmname = DNSQuery_RDATA_GetMG_MGMNAME(header, rdata);
        return new DNS_RData_MG(mgmname);
    }
    case EDNSQuery_RR_TYPE::TYPE_MINFO: {
        const std::string rmailbx = DNSQuery_RDATA_GetMINFO_RMAILBX(header, rdata);
        const std::string emailbx = DNSQuery_RDATA_GetMINFO_EMAILBX(header, rdata);
        return new DNS_RData_MINFO(rmailbx, emailbx);
    }
    case EDNSQuery_RR_TYPE::TYPE_MR: {
        const std::string newname = DNSQuery_RDATA_GetMR_NEWNAME(header, rdata);
        return new DNS_RData_MR(newname);
    }
    case EDNSQuery_RR_TYPE::TYPE_MX: {
        const uint16_t preference = DNSQuery_RDATA_GetMX_PREFERENCE(rdata);
        const std::string exchange = DNSQuery_RDATA_GetMX_EXCHANGE(header, rdata);
        return new DNS_RData_MX(preference, exchange);
    }
    case EDNSQuery_RR_TYPE::TYPE_NULL: {
        const uint8_t *anything = DNSQuery_RDATA_GetNULL_Format<uint8_t>(rdata, rdlength);
        return new DNS_RData_NULL(std::vector<uint8_t>(anything, anything + rdlength));
    }
    case EDNSQuery_RR_TYPE::TYPE_NS: {
        const std::string nsdname = DNSQuery_RDATA_GetNS_NSDNAME(header, rdata);
        return new DNS_RData_NS(nsdname);
    }
    case EDNSQuery_RR_TYPE::TYPE_PTR: {
        const std::string nsdname = DNSQuery_RDATA_GetPTR_PTRDNAME(header, rdata);
        return new DNS_RData_PTR(nsdname);
    }
    case EDNSQuery_RR_TYPE::TYPE_SOA: {
        const std::string mname = DNSQuery_RDATA_GetSOA_MNAME(header, rdata);
        const std::string rname = DNSQuery_RDATA_GetSOA_RNAME(header, rdata);
        const uint32_t serial = DNSQuery_RDATA_GetSOA_SERIAL(rdata);
        const uint32_t refresh = DNSQuery_RDATA_GetSOA_REFRESH(rdata);
        const uint32_t retry = DNSQuery_RDATA_GetSOA_RETRY(rdata);
        const uint32_t expire = DNSQuery_RDATA_GetSOA_EXPIRE(rdata);
        const uint32_t minimum = DNSQuery_RDATA_GetSOA_MINIMUM(rdata);
        return new DNS_RData_SOA(mname, rname, serial, refresh, retry, expire, minimum);
    }
    case EDNSQuery_RR_TYPE::TYPE_TXT: {
        const std::vector<std::string> txtdata = DNSQuery_RDATA_GetTXT_TXTDATA(rdata, rdlength);
        return new DNS_RData_TXT(txtdata);
    }
    case EDNSQuery_RR_TYPE::TYPE_WKS: {
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

DNS_Record::DNS_Record(const std::string& name, EDNSQuery_RR_TYPE type, EDNSQuery_RR_CLASS klass, uint32_t ttl, DNS_RData* data)
{
    m_name = name;
    m_type = type;
    m_class = klass;
    m_ttl = ttl;
    m_rdata = data;
}

bool DNS_Message::is_data_query(const char* msg_buf, uint32_t buf_size)
{
    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)msg_buf;

    if (!msg_buf || buf_size < DNSQuery_MessageHeader_GetDataSize(header)) {
        return false;
    }

    uint16_t flags = DNSQuery_MessageHeader_GetFlags(header);

    // This is a response
    if (FLAGS_GET_RESPONSE(flags)) {
        return false;
    }

    // DNS Queries must have this set to 0 (OPERATION_QUERY)
    if (FLAGS_GET_OPERATION_CODE(flags) != EDNSQuery_OperationCode::OPERATION_QUERY) {
        return false;
    }

    // DNS Queries have the reserved flag as 0
    if (FLAGS_GET_RESERVED(flags) != 0) {
        return false;
    }

    // DNS Queries have few questions but not 0
    const uint16_t qdcount = DNSQuery_MessageHeader_GetQDCount(header);
    if (qdcount == 0 || qdcount >= 10) {
        return false;
    }

    return true;
}

bool DNS_Message::is_data_response(const char* msg_buf, uint32_t buf_size)
{
    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)msg_buf;

    if (!msg_buf || buf_size < DNSQuery_MessageHeader_GetDataSize(header)) {
        return false;
    }

    uint16_t flags = DNSQuery_MessageHeader_GetFlags(header);

    // This is a query
    if (!FLAGS_GET_RESPONSE(flags)) {
        return false;
    }

    // DNS Responses must have this set to 0 (OPERATION_QUERY)
    if (FLAGS_GET_OPERATION_CODE(flags) != EDNSQuery_OperationCode::OPERATION_QUERY) {
        return false;
    }

    // DNS Responses have standard return code range 0-5
    if (FLAGS_GET_RETURN_CODE(flags) > EDNSQuery_ReturnCode::RETURN_REFUSED) {
        return false;
    }

    // DNS Responses typically contain the original question
    const uint16_t qdcount = DNSQuery_MessageHeader_GetQDCount(header);
    if (qdcount == 0 || qdcount >= 10) {
        return false;
    }

    return true;
}

DNS_Message* DNS_Message::create_query(uint16_t transaction_id)
{
    DNS_Message* msg = new DNS_Message();
    msg->set_id(transaction_id);

    uint16_t flags = 0;
    msg->set_flags(flags);

    return msg;
}

DNS_Message* DNS_Message::create_response(const DNS_Message* query)
{
    if (!query) {
        return nullptr;
    }

    DNS_Message* msg = new DNS_Message();

    // A valid response must echo the original Transaction ID
    msg->set_id(query->id());

    // A valid response must echo the original Question(s)
    for (const auto& q : query->questions()) {
        msg->add_question(q);
    }

    uint16_t flags = query->flags();
    flags |= FLAG_REQUEST_RESPONSE_MASK;
    msg->set_flags(flags);

    return msg;
}

DNS_Message* DNS_Message::create(const char* dns_buf, int buflen)
{
    const DNSQuery_MessageHeader* header = (DNSQuery_MessageHeader*)dns_buf;

    if (!dns_buf || buflen < DNSQuery_MessageHeader_GetDataSize(header)) {
        return nullptr;
    }

    const void* next_section = nullptr; // Used for incrementing pointers

    const uint16_t message_id = DNSQuery_MessageHeader_GetID(header);
    const uint16_t message_flags = DNSQuery_MessageHeader_GetFlags(header);
    const uint16_t message_qdcount = DNSQuery_MessageHeader_GetQDCount(header);
    const uint16_t message_ancount = DNSQuery_MessageHeader_GetANCount(header);
    const uint16_t message_nscount = DNSQuery_MessageHeader_GetNSCount(header);
    const uint16_t message_arcount = DNSQuery_MessageHeader_GetARCount(header);

    next_section = _DNS_OffsetPtr<void>(header, DNSQuery_MessageHeader_GetDataSize(header));

    auto LoadQuestionWithAdvance = [&next_section](const DNSQuery_MessageHeader* header) -> DNS_Question {
        const DNSQuery_QuestionSection* question = static_cast<const DNSQuery_QuestionSection*>(next_section);

        const std::string question_name = DNSQuery_Question_GetQNAME(header, question);
        const EDNSQuery_RR_QTYPE question_type = DNSQuery_Question_GetQTYPE(header, question);
        const EDNSQuery_RR_QCLASS question_class = DNSQuery_Question_GetQCLASS(header, question);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_Question_GetDataSize(header, question));

        return DNS_Question(question_name, question_type, question_class);
    };

    auto LoadResourceRecordWithAdvance = [&next_section](const DNSQuery_MessageHeader* header) -> DNS_Record {
        const DNSQuery_ResourceRecordSection* answer = static_cast<const DNSQuery_ResourceRecordSection*>(next_section);

        const std::string answer_name = DNSQuery_ResourceRecord_GetQNAME(header, answer);
        const EDNSQuery_RR_TYPE answer_type = DNSQuery_ResourceRecord_GetTYPE(header, answer);
        const EDNSQuery_RR_CLASS answer_class = DNSQuery_ResourceRecord_GetCLASS(header, answer);
        const uint32_t answer_ttl = DNSQuery_ResourceRecord_GetTTL(header, answer);
        const uint32_t answer_rdlength = DNSQuery_ResourceRecord_GetRDLENGTH(header, answer);

        const DNSQuery_RDATA* answer_low_rdata = DNSQuery_ResourceRecord_GetRDATA(header, answer);
        DNS_RData* answer_rdata = ParseRData(header, answer_type, answer_class, answer_rdlength, answer_low_rdata);

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_ResourceRecord_GetDataSize(header, answer));

        return DNS_Record(answer_name, answer_type, answer_class, answer_ttl, answer_rdata);
    };

    DNS_Message* result = new DNS_Message();
    result->m_id = message_id;
    result->m_flags = message_flags;

    // Process question entries
    for (uint16_t i = 0; i < message_qdcount; ++i) {
        result->m_questions.emplace_back(
            std::move(LoadQuestionWithAdvance(header)));
    }

    // Process answer entries
    for (uint16_t i = 0; i < message_ancount; ++i) {
        result->m_answers.emplace_back(
            std::move(LoadResourceRecordWithAdvance(header)));
    }

    // Process authoritative entries
    for (uint16_t i = 0; i < message_nscount; ++i) {
        result->m_authoritatives.emplace_back(
            std::move(LoadResourceRecordWithAdvance(header)));
    }

    // Process additional entries
    for (uint16_t i = 0; i < message_arcount; ++i) {
        result->m_additionals.emplace_back(
            std::move(LoadResourceRecordWithAdvance(header)));
    }

    return result;
}

const char* DNS_Message::build_buf(const DNS_Message& msg, uint32_t* size_out)
{
    if (!size_out) {
        return nullptr;
    }

    std::vector<uint8_t> dyn_buf;
    dyn_buf.reserve(512); // Pre-allocate standard UDP limit to avoid reallocation
    dyn_buf.resize(DNSQuery_MessageHeader_GetDataSize(nullptr), 0);

    // Set up the header
    // Safe to use data() here because we do all header writes before pushing new data
    DNSQuery_MessageHeader* header = reinterpret_cast<DNSQuery_MessageHeader*>(dyn_buf.data());
    {
        DNSQuery_MessageHeader_SetID(header, msg.m_id);
        DNSQuery_MessageHeader_SetFlags(header, msg.m_flags);
        DNSQuery_MessageHeader_SetQDCount(header, static_cast<uint16_t>(msg.m_questions.size()));
        DNSQuery_MessageHeader_SetANCount(header, static_cast<uint16_t>(msg.m_answers.size()));
        DNSQuery_MessageHeader_SetNSCount(header, static_cast<uint16_t>(msg.m_authoritatives.size()));
        DNSQuery_MessageHeader_SetARCount(header, static_cast<uint16_t>(msg.m_additionals.size()));
    }

    std::unordered_map<std::string, uint16_t> dname_to_pointer_map;

    // Returns the index that comes directly after this domain name in the buffer
    auto StoreDomainNameWithAdvance = [&dname_to_pointer_map](std::vector<uint8_t>& out, const std::string& dname) -> ptrdiff_t {
        if (dname.empty() || dname == ".") {
            out.push_back(0);
            return out.size();
        }

        // In this case we store it as a compressed ptr
        if (dname_to_pointer_map.find(dname) != dname_to_pointer_map.end()) {
            const uint16_t pointer = dname_to_pointer_map.at(dname);

            // DNS compression pointer: top 2 bits must be 11 (0xC000)
            uint16_t compressed_ptr = 0xC000 | pointer;

            size_t offset = out.size();
            out.resize(out.size() + 2);
            _DNS_WriteUnaligned16(out.data() + offset, compressed_ptr);

            return out.size();
        }

        // Store as an uncompressed domain name and cache to the dname pointer map
        dname_to_pointer_map[dname] = static_cast<uint16_t>(out.size());

        // Parse the dname (Example: "www.google.com" -> \x03www\x06google\x03com\x00)
        size_t start = 0;
        while (start < dname.length()) {
            size_t end = dname.find('.', start);
            if (end == std::string::npos) {
                end = dname.length();
            }

            size_t len = end - start;
            if (len > 0) {
                out.push_back(static_cast<uint8_t>(len));
                for (size_t i = 0; i < len; ++i) {
                    out.push_back(dname[start + i]);
                }
            }
            start = end + 1;
        }
        out.push_back(0); // NULL terminator
        return out.size();
    };

    // Helper to write raw 16/32 bit integers to the back of the vector
    auto Push16 = [](std::vector<uint8_t>& out, uint16_t val) {
        size_t offset = out.size();
        out.resize(out.size() + 2);
        _DNS_WriteUnaligned16(out.data() + offset, val);
    };
    auto Push32 = [](std::vector<uint8_t>& out, uint32_t val) {
        size_t offset = out.size();
        out.resize(out.size() + 4);
        _DNS_WriteUnaligned32(out.data() + offset, val);
    };

    for (const DNS_Question& question : msg.m_questions) {
        StoreDomainNameWithAdvance(dyn_buf, question.m_name);
        Push16(dyn_buf, static_cast<uint16_t>(question.m_type));
        Push16(dyn_buf, static_cast<uint16_t>(question.m_class));
    }

    // Generalized Record Serializer Lambda
    auto SerializeRecord = [&](const DNS_Record& record) {
        StoreDomainNameWithAdvance(dyn_buf, record.m_name);
        Push16(dyn_buf, static_cast<uint16_t>(record.m_type));
        Push16(dyn_buf, static_cast<uint16_t>(record.m_class));
        Push32(dyn_buf, record.m_ttl);

        // Save the index for RDLENGTH, push 2 dummy bytes
        size_t rdlength_index = dyn_buf.size();
        dyn_buf.push_back(0);
        dyn_buf.push_back(0);

        size_t rdata_start = dyn_buf.size();

        // Serialize the specific RDATA
        if (record.m_rdata) {
            switch (record.m_type) {
            case EDNSQuery_RR_TYPE::TYPE_A:
                Push32(dyn_buf, static_cast<const DNS_RData_A*>(record.m_rdata)->address());
                break;
            case EDNSQuery_RR_TYPE::TYPE_CNAME:
                StoreDomainNameWithAdvance(dyn_buf, static_cast<const DNS_RData_CNAME*>(record.m_rdata)->cname());
                break;
            case EDNSQuery_RR_TYPE::TYPE_HINFO: {
                auto* hinfo = static_cast<const DNS_RData_HINFO*>(record.m_rdata);

                uint8_t cpu_len = static_cast<uint8_t>(std::min(hinfo->cpu().length(), (size_t)255));
                dyn_buf.push_back(cpu_len);
                dyn_buf.insert(dyn_buf.end(), hinfo->cpu().begin(), hinfo->cpu().begin() + cpu_len);

                uint8_t os_len = static_cast<uint8_t>(std::min(hinfo->os().length(), (size_t)255));
                dyn_buf.push_back(os_len);
                dyn_buf.insert(dyn_buf.end(), hinfo->os().begin(), hinfo->os().begin() + os_len);
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MB: {
                auto* mb = static_cast<const DNS_RData_MB*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, mb->madname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MD: {
                auto* md = static_cast<const DNS_RData_MD*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, md->madname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MF: {
                auto* mf = static_cast<const DNS_RData_MF*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, mf->madname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MG: {
                auto* mg = static_cast<const DNS_RData_MG*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, mg->mgmname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MINFO: {
                auto* minfo = static_cast<const DNS_RData_MINFO*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, minfo->rmailbx());
                StoreDomainNameWithAdvance(dyn_buf, minfo->emailbx());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MR: {
                auto* mr = static_cast<const DNS_RData_MR*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, mr->newname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_MX: {
                auto* mx = static_cast<const DNS_RData_MX*>(record.m_rdata);
                Push16(dyn_buf, mx->preference());
                StoreDomainNameWithAdvance(dyn_buf, mx->exchange());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_NULL: {
                auto* null_rd = static_cast<const DNS_RData_NULL*>(record.m_rdata);
                dyn_buf.insert(dyn_buf.end(), null_rd->data().begin(), null_rd->data().end());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_NS: {
                auto* ns = static_cast<const DNS_RData_NS*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, ns->nsdname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_PTR: {
                auto* ptr = static_cast<const DNS_RData_PTR*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, ptr->ptrdname());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_SOA: {
                auto* soa = static_cast<const DNS_RData_SOA*>(record.m_rdata);
                StoreDomainNameWithAdvance(dyn_buf, soa->mname());
                StoreDomainNameWithAdvance(dyn_buf, soa->rname());
                Push32(dyn_buf, soa->serial());
                Push32(dyn_buf, soa->refresh());
                Push32(dyn_buf, soa->retry());
                Push32(dyn_buf, soa->expire());
                Push32(dyn_buf, soa->minimum());
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_TXT: {
                const DNS_RData_TXT* txt = static_cast<const DNS_RData_TXT*>(record.m_rdata);
                for (const std::string& str : txt->txtdata()) {
                    const uint8_t len = static_cast<uint8_t>(std::min(str.length(), (size_t)255));
                    dyn_buf.push_back(len);
                    dyn_buf.insert(dyn_buf.end(), str.begin(), str.begin() + len);
                }
                break;
            }
            case EDNSQuery_RR_TYPE::TYPE_WKS: {
                const DNS_RData_WKS* wks = static_cast<const DNS_RData_WKS*>(record.m_rdata);
                Push32(dyn_buf, wks->address()); // IPv4 Address
                dyn_buf.push_back(wks->protocol()); // 8-bit Protocol
                dyn_buf.insert(dyn_buf.end(), wks->bitmap().begin(), wks->bitmap().end()); // Variable Bit Map
                break;
            }
            default:
                break;
            }
        }

        size_t rdata_end = dyn_buf.size();
        uint16_t rdlength = static_cast<uint16_t>(rdata_end - rdata_start);
        _DNS_WriteUnaligned16(dyn_buf.data() + rdlength_index, rdlength);
    };

    for (const DNS_Record& answer : msg.m_answers) {
        SerializeRecord(answer);
    }

    for (const DNS_Record& authoritative : msg.m_authoritatives) {
        SerializeRecord(authoritative);
    }

    for (const DNS_Record& additional : msg.m_additionals) {
        SerializeRecord(additional);
    }

    // Finalize output
    *size_out = static_cast<uint32_t>(dyn_buf.size());
    char* final_buf = new char[*size_out];
    std::memcpy(final_buf, dyn_buf.data(), *size_out);

    return final_buf;
}

bool DNS_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags)
{
    if (DNS_Message::is_data_query(data, size)) {
        DNS_Message* message = DNS_Message::create(data, size);
        if (!message) {
            return false;
        }

        const DNS_Message* response = pipe->signal_dns_request(message);
        if (response) {
            pipe->send(response);
            delete response;
        }

        delete message;
        return true;
    }

    if (DNS_Message::is_data_response(data, size)) {
        DNS_Message* message = DNS_Message::create(data, size);
        if (!message) {
            return false;
        }

        const DNS_Message* request = pipe->signal_dns_response(message);
        if (request) {
            pipe->send(request);
            delete request;
        }

        delete message;
        return true;
    }
    return false;
}

uint32_t DNS_ApplicationAdapter::calc_size(const char* data, uint32_t size) const
{
    // DNS over UDP fits in a single packet
    return m_is_tcp ? _DNS_ReadUnaligned16(data) : size;
}

uint32_t DNS_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const
{
    uint32_t calc = calc_size(data, size);
    if (calc <= size) {
        return 0;
    }
    return calc - size;
}

bool DNS_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const
{
    return calc_proc_size(data, size) > 0;
}

}

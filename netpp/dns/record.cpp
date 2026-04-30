// ------------------------------------
// The following code is based on
// RFC1002, RFC1035, ..., and the Microsoft Docs
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <array>
#include <iostream>
#include <string>
#include <type_traits>

#include "netpp/dns/rr_impl/common.h"
#include "netpp/dns/record.h"
#include "netpp/netpp.h"
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

// --- Loaders --- //
extern netpp::DNS_RData* RR_A_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_NS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MD_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MF_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_CNAME_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_SOA_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MB_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MG_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MR_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_NULL_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_WKS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_PTR_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_HINFO_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MINFO_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_MX_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_TXT_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_AAAA_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_DNSKEY_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_RRSIG_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_DS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
extern netpp::DNS_RData* RR_NSEC_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);

// --- Storers --- //
extern uint16_t RR_A_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_NS_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MD_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MF_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_CNAME_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_SOA_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MB_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MG_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MR_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_NULL_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_WKS_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_PTR_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_HINFO_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MINFO_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_MX_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_TXT_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_AAAA_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_DNSKEY_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_RRSIG_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_DS_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
extern uint16_t RR_NSEC_Storer(netpp::DNS_StorerState &, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

static const auto s_rr_loaders = []() -> std::vector<netpp::DNS_RR_Loader> {
    std::vector<netpp::DNS_RR_Loader> out((size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MAX, nullptr);

    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_A] = RR_A_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NS] = RR_NS_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MD] = RR_MD_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MF] = RR_MF_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_CNAME] = RR_CNAME_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_SOA] = RR_SOA_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MB] = RR_MB_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MG] = RR_MG_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MR] = RR_MR_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NULL] = RR_NULL_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_WKS] = RR_WKS_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_PTR] = RR_PTR_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_HINFO] = RR_HINFO_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MINFO] = RR_MINFO_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MX] = RR_MX_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_TXT] = RR_TXT_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_AAAA] = RR_AAAA_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_DS] = RR_DS_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_RRSIG] = RR_RRSIG_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NSEC] = RR_NSEC_Loader;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_DNSKEY] = RR_DNSKEY_Loader;

    return out;
}();

static const auto s_rr_storers = []() -> std::vector<netpp::DNS_RR_Storer> {
    std::vector<netpp::DNS_RR_Storer> out((size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MAX, nullptr);

    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_A] = RR_A_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NS] = RR_NS_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MD] = RR_MD_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MF] = RR_MF_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_CNAME] = RR_CNAME_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_SOA] = RR_SOA_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MB] = RR_MB_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MG] = RR_MG_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MR] = RR_MR_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NULL] = RR_NULL_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_WKS] = RR_WKS_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_PTR] = RR_PTR_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_HINFO] = RR_HINFO_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MINFO] = RR_MINFO_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_MX] = RR_MX_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_TXT] = RR_TXT_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_AAAA] = RR_AAAA_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_DS] = RR_DS_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_RRSIG] = RR_RRSIG_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_NSEC] = RR_NSEC_Storer;
    out[(size_t)netpp::EDNSQuery_RR_TYPE::TYPE_DNSKEY] = RR_DNSKEY_Storer;

    return out;
}();

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

static void DNSQuery_MessageHeader_SetID(DNSQuery_MessageHeader* h, uint16_t id)
{
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

static uint64_t DNSQuery_RDATA_GetAAAA_ADDRESS_UPPER(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned64(rdata);
}

static uint64_t DNSQuery_RDATA_GetAAAA_ADDRESS_LOWER(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned64(_DNS_OffsetPtr<void>(rdata, 8));
}

static void DNSQuery_RDATA_SetAAAA_ADDRESS(DNSQuery_RDATA* rdata, uint64_t upper, uint64_t lower)
{
    _DNS_WriteUnaligned64(rdata, upper);
    _DNS_WriteUnaligned64(_DNS_OffsetPtr<void>(rdata, 8), upper);
}

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
}// RFC 1035 - 4.1.3 //
// ---------------- //

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

static bool IsAddressIPV4(const char* ip_addr)
{
    const uint32_t str_len = static_cast<uint32_t>(strnlen(ip_addr, IPV6_MAX_SIZE));
    if (str_len > IPV4_MAX_SIZE) {
        return false;
    }

    const char* seg_ptr = ip_addr;
    int segments_found = 0;
    while (segments_found < 4) {
        const char* seg_end = strchr(seg_ptr, '.');
        if (!seg_end) {
            if (segments_found < 3) {
                return false; // Not enough segments have been processed
            }

            seg_end = ip_addr + str_len;
        } else {
            if (segments_found == 3) {
                return false; // More than four segments to be processed
            }
        }

        const uint32_t digits = static_cast<uint32_t>(std::distance(seg_ptr, seg_end));
        if (digits == 0 || digits > 3) {
            return false; // Each octet is only up to 3 characters
        }

        int octet = 0;
        for (uint32_t i = 0; i < digits; ++i) {
            if (!isdigit(seg_ptr[i])) {
                return false; // Each octet is decimal only
            }
            octet = (octet * 10) + (seg_ptr[i] - '0');
        }

        if (octet > 255) {
            return false; // Octets are up to 255
        }

        segments_found += 1;
        seg_ptr = seg_end + 1;
    }

    return std::distance(ip_addr, seg_ptr) >= str_len;
}

static bool IsAddressIPV6(const char* ip_addr)
{
    if (!ip_addr) {
        return false;
    }

    // A standard IPv6 string cannot exceed 39 characters
    const uint32_t str_len = static_cast<uint32_t>(strnlen(ip_addr, IPV6_MAX_SIZE + 1));
    if (str_len < 2 || str_len > IPV6_MAX_SIZE) {
        return false;
    }

    int segments = 0;
    int current_hex_digits = 0;
    bool has_double_colon = false;

    for (uint32_t i = 0; i < str_len; ++i) {
        char c = ip_addr[i];

        if (isxdigit(c)) {
            current_hex_digits++;
            if (current_hex_digits > 4) {
                return false; // Maximum of 4 hex digits per segment
            }
        } else if (c == ':') {
            if (i > 0 && ip_addr[i - 1] == ':') {
                // We found a double colon "::"
                if (has_double_colon) {
                    return false; // Only one "::" is permitted per address
                }
                has_double_colon = true;
            } else {
                // It's a regular colon.
                // If it's the very first character, it's invalid unless followed by another ':'
                if (i == 0 && i + 1 < str_len && ip_addr[i + 1] != ':') {
                    return false;
                }

                // If we had digits before this colon, a segment is complete
                if (current_hex_digits > 0) {
                    segments++;
                    current_hex_digits = 0;
                }
            }
        } else {
            return false; // Invalid character found (e.g., '.', '-', letters beyond 'f')
        }
    }

    // Account for the final segment if the string ended in digits
    if (current_hex_digits > 0) {
        segments++;
    } else if (str_len > 0 && ip_addr[str_len - 1] == ':' && ip_addr[str_len - 2] != ':') {
        // The address ends with a single colon (e.g., "1:2:3:"), which is invalid format
        return false;
    }

    // A valid IPv6 has exactly 8 segments, OR less than 8 if zero compression (::) was used
    if (has_double_colon) {
        return segments < 8;
    } else {
        return segments == 8;
    }
}

static std::string ReverseLookupIPV4(const char* ip_addr)
{
    const uint32_t str_len = static_cast<uint32_t>(strnlen(ip_addr, IPV4_MAX_SIZE));

    std::string lookup_name(str_len, '\0');
    int lookup_name_idx = (int)lookup_name.size();

    lookup_name.append(".in-addr.arpa");

    const char* seg_ptr = ip_addr;
    int segments_found = 0;
    while (segments_found < 4) {
        const char* seg_end = strchr(seg_ptr, '.');
        if (!seg_end) {
            seg_end = ip_addr + str_len;
        }

        const uint32_t digits = static_cast<uint32_t>(std::distance(seg_ptr, seg_end));
        lookup_name_idx -= digits;

        strncpy(lookup_name.data() + lookup_name_idx, seg_ptr, digits);
        if (lookup_name_idx > 1) { // Write the . if theres more left
            lookup_name.data()[--lookup_name_idx] = '.';
        }

        segments_found += 1;
        seg_ptr = seg_end + 1;
    }

    return lookup_name;
}

static std::string ReverseLookupIPV6(const char* ip_addr)
{
    if (!ip_addr)
        return "";

    // 1. Parse into 8 blocks (required to expand "::" before formatting)
    uint16_t blocks[8] = { 0 };
    int num_blocks = 0;
    int gap_idx = -1;
    const char* ptr = ip_addr;

    if (ptr[0] == ':' && ptr[1] == ':') {
        gap_idx = 0;
        ptr += 2;
    }

    while (*ptr) {
        int hex_val = 0;
        int digits = 0;
        while (isxdigit(*ptr)) {
            if (digits >= 4)
                return "";
            int val = isdigit(*ptr) ? (*ptr - '0') : (tolower(*ptr) - 'a' + 10);
            hex_val = (hex_val << 4) | val;
            ptr++;
            digits++;
        }
        if (digits > 0)
            blocks[num_blocks++] = static_cast<uint16_t>(hex_val);

        if (*ptr == ':') {
            ptr++;
            if (*ptr == ':') {
                if (gap_idx != -1)
                    return "";
                gap_idx = num_blocks;
                ptr++;
            } else if (*ptr == '\0') {
                return "";
            }
        } else if (*ptr != '\0') {
            return "";
        }
    }

    // Expand the zero-compression gap
    if (gap_idx != -1) {
        int missing = 8 - num_blocks;
        if (missing < 0)
            return "";
        for (int i = num_blocks - 1; i >= gap_idx; --i) {
            blocks[i + missing] = blocks[i];
        }
        for (int i = 0; i < missing; ++i) {
            blocks[gap_idx + i] = 0;
        }
    } else if (num_blocks != 8) {
        return "";
    }

    // 2. Format backwards using manual buffer indexing
    // 32 hex nibbles + 32 dots = exactly 64 characters for the prefix.
    std::string lookup_name(64, '\0');
    int lookup_name_idx = (int)lookup_name.size();

    // Append the suffix (it attaches immediately after the 64th character)
    // We use "ip6.arpa" (no leading dot) because the 64th char will be the final dot.
    lookup_name.append("ip6.arpa");

    const char hex_chars[] = "0123456789abcdef";

    // Read blocks left-to-right (Block 0 is the most significant)
    for (int i = 0; i < 8; ++i) {
        uint16_t block = blocks[i];

        // Read nibbles left-to-right (High nibble down to low nibble)
        for (int nibble = 3; nibble >= 0; --nibble) {
            int val = (block >> (nibble * 4)) & 0xF;

            // Move index backwards by 2 (one for the dot, one for the hex char)
            lookup_name_idx -= 2;

            // Write directly into the buffer, mimicking the strncpy approach
            lookup_name.data()[lookup_name_idx] = hex_chars[val];
            lookup_name.data()[lookup_name_idx + 1] = '.';
        }
    }

    return lookup_name;
}

std::string
get_reverse_lookup_domain_name(const char* ip_addr)
{
    if (IsAddressIPV4(ip_addr)) {
        return ReverseLookupIPV4(ip_addr);
    }

    if (IsAddressIPV6(ip_addr)) {
        return ReverseLookupIPV6(ip_addr);
    }

    return std::string();
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
        const DNSQuery_ResourceRecordSection* rr = static_cast<const DNSQuery_ResourceRecordSection*>(next_section);

        const std::string rr_name = DNSQuery_ResourceRecord_GetQNAME(header, rr);
        const EDNSQuery_RR_TYPE rr_type = DNSQuery_ResourceRecord_GetTYPE(header, rr);
        const EDNSQuery_RR_CLASS rr_class = DNSQuery_ResourceRecord_GetCLASS(header, rr);
        const uint32_t rr_ttl = DNSQuery_ResourceRecord_GetTTL(header, rr);
        const uint32_t rr_rdlength = DNSQuery_ResourceRecord_GetRDLENGTH(header, rr);

        const DNSQuery_RDATA* rr_low_rdata = DNSQuery_ResourceRecord_GetRDATA(header, rr);
        const DNS_RR_Loader rr_loader = s_rr_loaders.at(static_cast<size_t>(rr_type));

        DNS_RData* rr_rdata = rr_loader ? rr_loader(header, rr_rdlength, rr_low_rdata, rr_class) : nullptr;

        next_section = _DNS_OffsetPtr<void>(next_section, DNSQuery_ResourceRecord_GetDataSize(header, rr));

        return DNS_Record(rr_name, rr_type, rr_class, rr_ttl, rr_rdata);
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

    DNS_StorerState state;
    state.m_out.reserve(2048);
    state.m_out.resize(DNSQuery_MessageHeader_GetDataSize(nullptr), 0);
    state.m_header_idx = 0;
    state.m_dname_to_pointer_cache = {};

    // Set up the header
    // Safe to use data() here because we do all header writes before pushing new data
    DNSQuery_MessageHeader* header = reinterpret_cast<DNSQuery_MessageHeader*>(state.m_out.data());
    {
        DNSQuery_MessageHeader_SetID(header, msg.m_id);
        DNSQuery_MessageHeader_SetFlags(header, msg.m_flags);
        DNSQuery_MessageHeader_SetQDCount(header, static_cast<uint16_t>(msg.m_questions.size()));
        DNSQuery_MessageHeader_SetANCount(header, static_cast<uint16_t>(msg.m_answers.size()));
        DNSQuery_MessageHeader_SetNSCount(header, static_cast<uint16_t>(msg.m_authoritatives.size()));
        DNSQuery_MessageHeader_SetARCount(header, static_cast<uint16_t>(msg.m_additionals.size()));
    }

    for (const DNS_Question& question : msg.m_questions) {
        DNSQuery_StoreDomainNameWithAdvance(state, question.m_name);
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(question.m_type));
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(question.m_class));
    }

    // Generalized Record Serializer Lambda
    auto SerializeRecord = [&](const DNS_Record& record) {
        DNSQuery_StoreDomainNameWithAdvance(state, record.m_name);
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(record.m_type));
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(record.m_class));
        DNSQuery_Push32(state.m_out, record.m_ttl);

        // Save the index for RDLENGTH, push 2 dummy bytes
        const size_t rdlength_index = state.m_out.size();
        DNSQuery_Push16(state.m_out, 0);

        // Serialize the specific RDATA
        if (!record.m_rdata) {
            return;
        }

        const DNS_RR_Storer rr_storer = s_rr_storers.at(static_cast<size_t>(record.m_type));
        const uint16_t rdlength = rr_storer ? rr_storer(state, record.m_rdata, record.m_class) : 0;

        _DNS_WriteUnaligned16(state.m_out.data() + rdlength_index, rdlength);
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
    *size_out = static_cast<uint32_t>(state.m_out.size());
    char* final_buf = new char[*size_out];
    std::memcpy(final_buf, state.m_out.data(), *size_out);

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

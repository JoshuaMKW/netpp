// ------------------------------------
// The following code is based on
// RFC1002 and RFC1035
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#include <iostream>
#include <string>
#include <type_traits>

#include "netpp/dns/rr_impl/common.h"
#include "netpp/netpp.h"
#include "netpp/protocol.h"
#include "netpp/socket.h"

// --- Loaders --- //
netpp::DNS_RData* RR_A_Loader(const void *header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_NS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MD_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MF_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_CNAME_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_SOA_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MB_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MG_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MR_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_NULL_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_WKS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_PTR_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_HINFO_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MINFO_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_MX_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_TXT_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);

// --- Storers --- //
uint16_t RR_A_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NS_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MD_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MF_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_CNAME_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_SOA_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MB_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MG_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MR_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NULL_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_WKS_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_PTR_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_HINFO_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MINFO_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MX_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_TXT_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

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

static std::vector<uint8_t> DNSQuery_RDATA_GetWKS_BITMAP(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{

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

static uint16_t DNSQuery_RDATA_GetRRSIG_TYPECOVERED(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(rdata);
}

static void DNSQuery_RDATA_SetRRSIG_TYPECOVERED(DNSQuery_RDATA* rdata, uint16_t type_covered)
{
    _DNS_WriteUnaligned16(rdata, type_covered);
}

static uint8_t DNSQuery_RDATA_GetRRSIG_ALGORITHM(const DNSQuery_RDATA* rdata)
{
    return *_DNS_OffsetPtr<uint8_t>(rdata, 2);
}

static void DNSQuery_RDATA_SetRRSIG_ALGORITHM(DNSQuery_RDATA* rdata, uint8_t algorithm)
{
    *_DNS_OffsetPtr<uint8_t>(rdata, 2) = algorithm;
}

static uint8_t DNSQuery_RDATA_GetRRSIG_LABELS(const DNSQuery_RDATA* rdata)
{
    return *_DNS_OffsetPtr<uint8_t>(rdata, 3);
}

static void DNSQuery_RDATA_SetRRSIG_LABELS(DNSQuery_RDATA* rdata, uint8_t labels)
{
    *_DNS_OffsetPtr<uint8_t>(rdata, 3) = labels;
}

static uint32_t DNSQuery_RDATA_GetRRSIG_ORIGINALTTL(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(_DNS_OffsetPtr<void>(rdata, 4));
}

static void DNSQuery_RDATA_SetRRSIG_ORIGINALTTL(DNSQuery_RDATA* rdata, uint32_t ttl)
{
    _DNS_WriteUnaligned32(_DNS_OffsetPtr<void>(rdata, 4), ttl);
}

static uint32_t DNSQuery_RDATA_GetRRSIG_SIGEXPIRIATION(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(_DNS_OffsetPtr<void>(rdata, 8));
}

static void DNSQuery_RDATA_SetRRSIG_SIGEXPIRIATION(DNSQuery_RDATA* rdata, uint32_t expiration)
{
    _DNS_WriteUnaligned32(_DNS_OffsetPtr<void>(rdata, 8), expiration);
}

static uint32_t DNSQuery_RDATA_GetRRSIG_SIGINCEPTION(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned32(_DNS_OffsetPtr<void>(rdata, 12));
}

static void DNSQuery_RDATA_SetRRSIG_SIGINCEPTION(DNSQuery_RDATA* rdata, uint32_t inception)
{
    _DNS_WriteUnaligned32(_DNS_OffsetPtr<void>(rdata, 12), inception);
}

static uint16_t DNSQuery_RDATA_GetRRSIG_KEYTAG(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(rdata, 16));
}

static void DNSQuery_RDATA_SetRRSIG_KEYTAG(DNSQuery_RDATA* rdata, uint16_t keytag)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(rdata, 16), keytag);
}

static std::string DNSQuery_RDATA_GetRRSIG_SIGNERSNAME(const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetCharacterString(_DNS_OffsetPtr<uint8_t>(rdata, 18));
}

static std::vector<uint8_t> DNSQuery_RDATA_GetRRSIG_SIGNATURE(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    const uint16_t signers_name_len = DNSQuery_GetCharacterStringLength((uint8_t*)rdata);
    const uint8_t* signature_ptr = _DNS_OffsetPtr<uint8_t>(rdata, 18 + signers_name_len);

    const uint16_t signature_len = rdlength - (18 + signers_name_len);
    return std::vector(signature_ptr, signature_ptr + signature_len);
}

#define DNSKEY_FLAGS_HOLDS_ZONE_KEY(flags) ((bool)(((flags) >> 8) & 0b1))
#define DNSKEY_FLAGS_IS_SECURE_ENTRY_POINT(flags) ((bool)((flags) & 0b1))

static uint16_t DNSQuery_RDATA_GetDNSKEY_FLAGS(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(rdata);
}

static void DNSQuery_RDATA_SetDNSKEY_FLAGS(DNSQuery_RDATA* rdata, uint16_t flags)
{
    _DNS_WriteUnaligned16(rdata, flags);
}

static uint8_t DNSQuery_RDATA_GetDNSKEY_PROTOCOL(const DNSQuery_RDATA* rdata)
{
    return *_DNS_OffsetPtr<uint8_t>(rdata, 2);
}

static void DNSQuery_RDATA_SetDNSKEY_PROTOCOL(DNSQuery_RDATA* rdata, uint8_t protocol)
{
    *_DNS_OffsetPtr<uint8_t>(rdata, 2) = protocol;
}

static uint8_t DNSQuery_RDATA_GetDNSKEY_ALGORITHM(const DNSQuery_RDATA* rdata)
{
    return *_DNS_OffsetPtr<uint8_t>(rdata, 3);
}

static void DNSQuery_RDATA_SetDNSKEY_ALGORITHM(DNSQuery_RDATA* rdata, uint8_t algorithm)
{
    *_DNS_OffsetPtr<uint8_t>(rdata, 3) = algorithm;
}

static std::vector<uint8_t> DNSQuery_RDATA_GetDNSKEY_PUBLICKEY(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    const uint8_t* pubkey = _DNS_OffsetPtr<uint8_t>(rdata, 4);
    return std::vector(pubkey, pubkey + rdlength - 4);
}

// RFC 1035 - 4.1.2 //
// ---------------- //

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

// ----------------

netpp::DNS_RData* RR_A_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint32_t address = DNSQuery_RDATA_GetA_ADDRESS(rdata);
    return new netpp::DNS_RData_A(address);
}

netpp::DNS_RData* RR_CNAME_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string cname = DNSQuery_RDATA_GetCNAME(header, rdata);
    return new netpp::DNS_RData_CNAME(cname);
}

netpp::DNS_RData* RR_HINFO_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string cpu = DNSQuery_RDATA_GetHINFO_CPU(rdata);
    const std::string os = DNSQuery_RDATA_GetHINFO_OS(rdata);
    return new netpp::DNS_RData_HINFO(cpu, os);
}

netpp::DNS_RData* RR_MB_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMB_MADNAME(header, rdata);
    return new netpp::DNS_RData_MB(madname);
}

netpp::DNS_RData* RR_MD_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMD_MADNAME(header, rdata);
    return new netpp::DNS_RData_MD(madname);
}

netpp::DNS_RData* RR_MF_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMF_MADNAME(header, rdata);
    return new netpp::DNS_RData_MF(madname);
}

netpp::DNS_RData* RR_MG_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string mgmname = DNSQuery_RDATA_GetMG_MGMNAME(header, rdata);
    return new netpp::DNS_RData_MG(mgmname);
}

netpp::DNS_RData* RR_MINFO_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string rmailbx = DNSQuery_RDATA_GetMINFO_RMAILBX(header, rdata);
    const std::string emailbx = DNSQuery_RDATA_GetMINFO_EMAILBX(header, rdata);
    return new netpp::DNS_RData_MINFO(rmailbx, emailbx);
}

netpp::DNS_RData* RR_MR_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string newname = DNSQuery_RDATA_GetMR_NEWNAME(header, rdata);
    return new netpp::DNS_RData_MR(newname);
}

netpp::DNS_RData* RR_MX_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint16_t preference = DNSQuery_RDATA_GetMX_PREFERENCE(rdata);
    const std::string exchange = DNSQuery_RDATA_GetMX_EXCHANGE(header, rdata);
    return new netpp::DNS_RData_MX(preference, exchange);
}

netpp::DNS_RData* RR_NULL_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint8_t* anything = DNSQuery_RDATA_GetNULL_Format<uint8_t>(rdata, rdlength);
    return new netpp::DNS_RData_NULL(std::vector<uint8_t>(anything, anything + rdlength));
}

netpp::DNS_RData* RR_NS_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string nsdname = DNSQuery_RDATA_GetNS_NSDNAME(header, rdata);
    return new netpp::DNS_RData_NS(nsdname);
}

netpp::DNS_RData* RR_PTR_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string nsdname = DNSQuery_RDATA_GetPTR_PTRDNAME(header, rdata);
    return new netpp::DNS_RData_PTR(nsdname);
}

netpp::DNS_RData* RR_SOA_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string mname = DNSQuery_RDATA_GetSOA_MNAME(header, rdata);
    const std::string rname = DNSQuery_RDATA_GetSOA_RNAME(header, rdata);
    const uint32_t serial = DNSQuery_RDATA_GetSOA_SERIAL(rdata);
    const uint32_t refresh = DNSQuery_RDATA_GetSOA_REFRESH(rdata);
    const uint32_t retry = DNSQuery_RDATA_GetSOA_RETRY(rdata);
    const uint32_t expire = DNSQuery_RDATA_GetSOA_EXPIRE(rdata);
    const uint32_t minimum = DNSQuery_RDATA_GetSOA_MINIMUM(rdata);
    return new netpp::DNS_RData_SOA(mname, rname, serial, refresh, retry, expire, minimum);
}

netpp::DNS_RData* RR_TXT_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::vector<std::string> txtdata = DNSQuery_RDATA_GetTXT_TXTDATA(rdata, rdlength);
    return new netpp::DNS_RData_TXT(txtdata);
}

netpp::DNS_RData* RR_WKS_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint32_t address = DNSQuery_RDATA_GetWKS_ADDRESS(rdata);
    const uint8_t protocol = DNSQuery_RDATA_GetWKS_PROTOCOL(rdata);
    const std::vector<uint8_t> bitmap = DNSQuery_RDATA_GetWKS_BITMAP(rdata, rdlength);
    return new netpp::DNS_RData_WKS(address, protocol, bitmap);
}

namespace netpp {

std::string DNS_RData_A::ipv4() const
{
    return std::to_string((m_address >> 24) & 0xFF) + "." + std::to_string((m_address >> 16) & 0xFF) + "." + std::to_string((m_address >> 8) & 0xFF) + "." + std::to_string(m_address & 0xFF);
}

std::string DNS_RData_WKS::ipv4() const
{
    return std::to_string((m_address >> 24) & 0xFF) + "." + std::to_string((m_address >> 16) & 0xFF) + "." + std::to_string((m_address >> 8) & 0xFF) + "." + std::to_string(m_address & 0xFF);
}

std::string DNS_RData_AAAA::ipv6() const
{
    const uint16_t blocks[8] = {
        static_cast<uint16_t>(m_upper >> 48),
        static_cast<uint16_t>(m_upper >> 32),
        static_cast<uint16_t>(m_upper >> 16),
        static_cast<uint16_t>(m_upper),
        static_cast<uint16_t>(m_lower >> 48),
        static_cast<uint16_t>(m_lower >> 32),
        static_cast<uint16_t>(m_lower >> 16),
        static_cast<uint16_t>(m_lower)
    };

    // Find the longest consecutive run of zero blocks
    int max_zero_start = -1;
    int max_zero_len = 0;
    int current_zero_start = -1;
    int current_zero_len = 0;

    for (int i = 0; i < 8; ++i) {
        if (blocks[i] == 0) {
            if (current_zero_start == -1) {
                current_zero_start = i;
            }
            current_zero_len++;
        } else {
            if (current_zero_len > max_zero_len) {
                max_zero_len = current_zero_len;
                max_zero_start = current_zero_start;
            }
            current_zero_start = -1;
            current_zero_len = 0;
        }
    }
    // Catch if the zero run goes all the way to the end of the array
    if (current_zero_len > max_zero_len) {
        max_zero_len = current_zero_len;
        max_zero_start = current_zero_start;
    }

    // RFC 5952 Rule: "::" must not be used to shorten a single 16-bit 0 block
    if (max_zero_len <= 1) {
        max_zero_start = -1;
    }

    std::string result;
    result.reserve(IPV6_MAX_SIZE);
    char buf[5]; // Max size of a 16-bit hex string is 4 chars + null terminator

    for (int i = 0; i < 8; ++i) {
        if (i == max_zero_start) {
            result += "::";
            i += max_zero_len - 1; // Advance the iterator to the end of the zero run
            continue;
        }

        // Add a colon separator, EXCEPT:
        // - At the very beginning (i == 0)
        // - Immediately after a "::" was placed
        if (i != 0 && i != (max_zero_start + max_zero_len)) {
            result += ":";
        }

        snprintf(buf, sizeof(buf), "%x", blocks[i]);
        result += buf;
    }

    return result;
}

}
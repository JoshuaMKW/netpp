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
netpp::DNS_RData* RR_DNSKEY_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_RRSIG_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_DS_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);
netpp::DNS_RData* RR_NSEC_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);

// --- Storers --- //
uint16_t RR_DNSKEY_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_RRSIG_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_DS_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NSEC_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

static netpp::EDNSQuery_RR_TYPE DNSQuery_RDATA_GetRRSIG_TYPECOVERED(const DNSQuery_RDATA* rdata)
{
    return static_cast<netpp::EDNSQuery_RR_TYPE>(_DNS_ReadUnaligned16(rdata));
}

static void DNSQuery_RDATA_SetRRSIG_TYPECOVERED(DNSQuery_RDATA* rdata, netpp::EDNSQuery_RR_TYPE type_covered)
{
    _DNS_WriteUnaligned16(rdata, static_cast<uint16_t>(type_covered));
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

// ------------------

// RFC 1035 - 4.1.3 //
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

netpp::DNS_RData* RR_DNSKEY_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint16_t flags = DNSQuery_RDATA_GetDNSKEY_FLAGS(rdata);
    const uint8_t protocol = DNSQuery_RDATA_GetDNSKEY_PROTOCOL(rdata);
    const uint8_t algorithm = DNSQuery_RDATA_GetDNSKEY_ALGORITHM(rdata);
    const std::vector<uint8_t> publickey = DNSQuery_RDATA_GetDNSKEY_PUBLICKEY(rdata, rdlength);
    return new netpp::DNS_RData_DNSKEY(flags, protocol, algorithm, publickey);
}

netpp::DNS_RData* RR_RRSIG_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);

    const netpp::EDNSQuery_RR_TYPE type_covered = DNSQuery_RDATA_GetRRSIG_TYPECOVERED(rdata);
    const uint8_t algorithm = DNSQuery_RDATA_GetRRSIG_ALGORITHM(rdata);
    const uint8_t labels = DNSQuery_RDATA_GetRRSIG_LABELS(rdata);
    const uint32_t original_ttl = DNSQuery_RDATA_GetRRSIG_ORIGINALTTL(rdata);
    const uint32_t sig_expiration = DNSQuery_RDATA_GetRRSIG_SIGEXPIRIATION(rdata);
    const uint32_t sig_inception = DNSQuery_RDATA_GetRRSIG_SIGINCEPTION(rdata);
    const uint16_t key_tag = DNSQuery_RDATA_GetRRSIG_KEYTAG(rdata);

    uint16_t name_len = 0;
    const std::string signers_name = DNSQuery_RDATA_GetRRSIG_SIGNERSNAME(rdata);
    const std::vector<uint8_t> signature = DNSQuery_RDATA_GetRRSIG_SIGNATURE(rdata, rdlength);

    return nullptr;
    //return new netpp::DNS_RData_RRSIG(type_covered, algorithm, labels, original_ttl, sig_expiration, sig_inception, key_tag, signers_name, signature);
}

// Stubs for DS and NSEC to complete the set
netpp::DNS_RData* RR_DS_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    return nullptr;
}

netpp::DNS_RData* RR_NSEC_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    return nullptr;
}

namespace netpp {

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
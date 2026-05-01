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
uint16_t RR_DNSKEY_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_RRSIG_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_DS_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NSEC_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

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

static std::string DNSQuery_RDATA_GetRRSIG_SIGNERSNAME(const DNSQuery_MessageHeader* header, const DNSQuery_RDATA* rdata)
{
    return DNSQuery_GetDomainName(header, _DNS_OffsetPtr<uint8_t>(rdata, 18));
}

static std::vector<uint8_t> DNSQuery_RDATA_GetRRSIG_SIGNATURE(const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    const uint16_t signers_name_len = DNSQuery_GetCharacterStringLength((uint8_t*)rdata);
    const uint8_t* signature_ptr = _DNS_OffsetPtr<uint8_t>(rdata, 18 + signers_name_len);

    const uint16_t signature_len = rdlength - (18 + signers_name_len);
    return std::vector(signature_ptr, signature_ptr + signature_len);
}

static std::string DNSQuery_RDATA_GetNSEC_NEXTDOMAINNAME(const DNSQuery_MessageHeader* header, const DNSQuery_RDATA* rdata) {
    return DNSQuery_GetDomainName(header, _DNS_OffsetPtr<uint8_t>(rdata, 0));
}

static std::vector<uint8_t> DNSQuery_RDATA_GetNSEC_TYPEBITMAPS(const DNSQuery_MessageHeader* header, const DNSQuery_RDATA* rdata, uint16_t rdlength)
{
    const uint16_t nextdomain_len = DNSQuery_GetDomainNameCompressedSize(_DNS_OffsetPtr<uint8_t>(rdata, 0));
    const uint8_t* bitmaps_start = _DNS_OffsetPtr<uint8_t>(rdata, nextdomain_len);
    return std::vector<uint8_t>(bitmaps_start, bitmaps_start + (rdlength - nextdomain_len));
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
    const std::string signers_name = DNSQuery_RDATA_GetRRSIG_SIGNERSNAME(header, rdata);
    const std::vector<uint8_t> signature = DNSQuery_RDATA_GetRRSIG_SIGNATURE(rdata, rdlength);

    return new netpp::DNS_RData_RRSIG(type_covered, algorithm, labels, original_ttl, sig_expiration, sig_inception, key_tag, signers_name, signature);
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

uint16_t RR_DNSKEY_Storer(netpp::DNS_StorerState& state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS klass)
{
    return 0;
}

uint16_t RR_RRSIG_Storer(netpp::DNS_StorerState& state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS klass)
{
    return 0;
}

uint16_t RR_DS_Storer(netpp::DNS_StorerState& state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS klass)
{
    return 0;
}

uint16_t RR_NSEC_Storer(netpp::DNS_StorerState& state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS klass)
{
    return 0;
}

namespace netpp {

}
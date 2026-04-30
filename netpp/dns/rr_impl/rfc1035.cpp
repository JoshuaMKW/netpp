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
uint16_t RR_A_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NS_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MD_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MF_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_CNAME_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_SOA_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MB_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MG_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MR_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_NULL_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_WKS_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_PTR_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_HINFO_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MINFO_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_MX_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);
uint16_t RR_TXT_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

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
    const uint16_t rmailbx_len = DNSQuery_GetDomainNameCompressedSize(minfo);
    return DNSQuery_GetDomainName(h, minfo + rmailbx_len);
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
    while (marker < rdlength) {
        result.emplace_back(std::move(DNSQuery_GetCharacterString(strptr + marker)));
        marker += DNSQuery_GetCharacterStringLength(strptr + marker);
    }

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
    return (bool)((wks_bits[bit >> 3] >> (7 - (bit % 8))) & 1);
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

// ----------------

netpp::DNS_RData* RR_A_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint32_t address = DNSQuery_RDATA_GetA_ADDRESS(rdata);
    return new netpp::DNS_RData_A(address);
}

netpp::DNS_RData* RR_CNAME_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string cname = DNSQuery_RDATA_GetCNAME(header, rdata);
    return new netpp::DNS_RData_CNAME(cname);
}

netpp::DNS_RData* RR_HINFO_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string cpu = DNSQuery_RDATA_GetHINFO_CPU(rdata);
    const std::string os = DNSQuery_RDATA_GetHINFO_OS(rdata);
    return new netpp::DNS_RData_HINFO(cpu, os);
}

netpp::DNS_RData* RR_MB_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMB_MADNAME(header, rdata);
    return new netpp::DNS_RData_MB(madname);
}

netpp::DNS_RData* RR_MD_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMD_MADNAME(header, rdata);
    return new netpp::DNS_RData_MD(madname);
}

netpp::DNS_RData* RR_MF_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string madname = DNSQuery_RDATA_GetMF_MADNAME(header, rdata);
    return new netpp::DNS_RData_MF(madname);
}

netpp::DNS_RData* RR_MG_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string mgmname = DNSQuery_RDATA_GetMG_MGMNAME(header, rdata);
    return new netpp::DNS_RData_MG(mgmname);
}

netpp::DNS_RData* RR_MINFO_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string rmailbx = DNSQuery_RDATA_GetMINFO_RMAILBX(header, rdata);
    const std::string emailbx = DNSQuery_RDATA_GetMINFO_EMAILBX(header, rdata);
    return new netpp::DNS_RData_MINFO(rmailbx, emailbx);
}

netpp::DNS_RData* RR_MR_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string newname = DNSQuery_RDATA_GetMR_NEWNAME(header, rdata);
    return new netpp::DNS_RData_MR(newname);
}

netpp::DNS_RData* RR_MX_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint16_t preference = DNSQuery_RDATA_GetMX_PREFERENCE(rdata);
    const std::string exchange = DNSQuery_RDATA_GetMX_EXCHANGE(header, rdata);
    return new netpp::DNS_RData_MX(preference, exchange);
}

netpp::DNS_RData* RR_NULL_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint8_t* anything = DNSQuery_RDATA_GetNULL_Format<uint8_t>(rdata, rdlength);
    return new netpp::DNS_RData_NULL(std::vector<uint8_t>(anything, anything + rdlength));
}

netpp::DNS_RData* RR_NS_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string nsdname = DNSQuery_RDATA_GetNS_NSDNAME(header, rdata);
    return new netpp::DNS_RData_NS(nsdname);
}

netpp::DNS_RData* RR_PTR_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_MessageHeader* header = static_cast<const DNSQuery_MessageHeader*>(header_);
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::string nsdname = DNSQuery_RDATA_GetPTR_PTRDNAME(header, rdata);
    return new netpp::DNS_RData_PTR(nsdname);
}

netpp::DNS_RData* RR_SOA_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
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
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const std::vector<std::string> txtdata = DNSQuery_RDATA_GetTXT_TXTDATA(rdata, rdlength);
    return new netpp::DNS_RData_TXT(txtdata);
}

netpp::DNS_RData* RR_WKS_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint32_t address = DNSQuery_RDATA_GetWKS_ADDRESS(rdata);
    const uint8_t protocol = DNSQuery_RDATA_GetWKS_PROTOCOL(rdata);
    const std::vector<uint8_t> bitmap = DNSQuery_RDATA_GetWKS_BITMAP(rdata, rdlength);
    return new netpp::DNS_RData_WKS(address, protocol, bitmap);
}

uint16_t RR_A_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    DNSQuery_Push32(state.m_out, static_cast<const netpp::DNS_RData_A*>(rdata)->address());
    return 4;
}

uint16_t RR_NS_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_NS* ns = static_cast<const netpp::DNS_RData_NS*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, ns->nsdname());
}

uint16_t RR_MD_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MD* md = static_cast<const netpp::DNS_RData_MD*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, md->madname());
}

uint16_t RR_MF_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MF* mf = static_cast<const netpp::DNS_RData_MF*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, mf->madname());
}

uint16_t RR_CNAME_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    return DNSQuery_StoreDomainNameWithAdvance(state, static_cast<const netpp::DNS_RData_CNAME*>(rdata)->cname());
}

uint16_t RR_SOA_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_SOA* soa = static_cast<const netpp::DNS_RData_SOA*>(rdata);
    const uint16_t mname_len = DNSQuery_StoreDomainNameWithAdvance(state, soa->mname());
    const uint16_t rname_len = DNSQuery_StoreDomainNameWithAdvance(state, soa->rname());
    DNSQuery_Push32(state.m_out, soa->serial());
    DNSQuery_Push32(state.m_out, soa->refresh());
    DNSQuery_Push32(state.m_out, soa->retry());
    DNSQuery_Push32(state.m_out, soa->expire());
    DNSQuery_Push32(state.m_out, soa->minimum());
    return 20 + mname_len + rname_len;
}

uint16_t RR_MB_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MB* mb = static_cast<const netpp::DNS_RData_MB*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, mb->madname());
}

uint16_t RR_MG_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MG* mg = static_cast<const netpp::DNS_RData_MG*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, mg->mgmname());
}

uint16_t RR_MR_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MR* mr = static_cast<const netpp::DNS_RData_MR*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, mr->newname());
}

uint16_t RR_NULL_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_NULL* null_rd = static_cast<const netpp::DNS_RData_NULL*>(rdata);
    state.m_out.insert(state.m_out.end(), null_rd->data().begin(), null_rd->data().end());
    return null_rd->data().size();
}

uint16_t RR_WKS_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_WKS* wks = static_cast<const netpp::DNS_RData_WKS*>(rdata);
    DNSQuery_Push32(state.m_out, wks->address()); // IPv4 Address
    state.m_out.push_back(wks->protocol()); // 8-bit Protocol
    state.m_out.insert(state.m_out.end(), wks->bitmap().begin(), wks->bitmap().end()); // Variable Bit Map
    return 5 + wks->bitmap().size();
}

uint16_t RR_PTR_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_PTR* ptr = static_cast<const netpp::DNS_RData_PTR*>(rdata);
    return DNSQuery_StoreDomainNameWithAdvance(state, ptr->ptrdname());
}

uint16_t RR_HINFO_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_HINFO* hinfo = static_cast<const netpp::DNS_RData_HINFO*>(rdata);

    const uint8_t cpu_len = static_cast<uint8_t>(std::min(hinfo->cpu().length(), (size_t)255));
    state.m_out.push_back(cpu_len);
    state.m_out.insert(state.m_out.end(), hinfo->cpu().begin(), hinfo->cpu().begin() + cpu_len);

    const uint8_t os_len = static_cast<uint8_t>(std::min(hinfo->os().length(), (size_t)255));
    state.m_out.push_back(os_len);
    state.m_out.insert(state.m_out.end(), hinfo->os().begin(), hinfo->os().begin() + os_len);

    return 2 + cpu_len + os_len;
}

uint16_t RR_MINFO_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    auto* minfo = static_cast<const netpp::DNS_RData_MINFO*>(rdata);
    const uint16_t rmail_len = DNSQuery_StoreDomainNameWithAdvance(state, minfo->rmailbx());
    const uint16_t email_len = DNSQuery_StoreDomainNameWithAdvance(state, minfo->emailbx());
    return rmail_len + email_len;
}

uint16_t RR_MX_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    const netpp::DNS_RData_MX* mx = static_cast<const netpp::DNS_RData_MX*>(rdata);
    DNSQuery_Push16(state.m_out, mx->preference());
    return 2 + DNSQuery_StoreDomainNameWithAdvance(state, mx->exchange());
}

uint16_t RR_TXT_Storer(netpp::DNS_StorerState &state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS)
{
    uint16_t total_len = 0;

    const netpp::DNS_RData_TXT* txt = static_cast<const netpp::DNS_RData_TXT*>(rdata);
    for (const std::string& str : txt->txtdata()) {
        const uint8_t len = static_cast<uint8_t>(std::min(str.length(), (size_t)255));
        state.m_out.push_back(len);
        state.m_out.insert(state.m_out.end(), str.begin(), str.begin() + len);
        total_len += (1 + len);
    }

    return total_len;
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

}
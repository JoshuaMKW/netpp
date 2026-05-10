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
netpp::DNS_RData* RR_OPT_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);

// --- Storers --- //
uint16_t RR_OPT_Storer(netpp::DNS_StorerState&, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

#define DNSKEY_FLAGS_HOLDS_ZONE_KEY(flags) ((bool)(((flags) >> 8) & 0b1))
#define DNSKEY_FLAGS_IS_SECURE_ENTRY_POINT(flags) ((bool)((flags) & 0b1))

static uint16_t DNSQuery_RDATA_GetOPT_OPTIONCODE(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(rdata);
}

static void DNSQuery_RDATA_SetDNSKEY_OPTIONCODE(DNSQuery_RDATA* rdata, uint16_t option_code)
{
    _DNS_WriteUnaligned16(rdata, option_code);
}

static uint16_t DNSQuery_RDATA_GetOPT_OPTIONLENGTH(const DNSQuery_RDATA* rdata)
{
    return _DNS_ReadUnaligned16(_DNS_OffsetPtr<void>(rdata, 2));
}

static void DNSQuery_RDATA_SetOPT_OPTIONLENGTH(DNSQuery_RDATA* rdata, uint16_t option_length)
{
    _DNS_WriteUnaligned16(_DNS_OffsetPtr<void>(rdata, 2), option_length);
}

static std::vector<uint8_t> DNSQuery_RDATA_GetOPT_OPTIONDATA(const DNSQuery_RDATA* rdata)
{
    const uint16_t option_length = DNSQuery_RDATA_GetOPT_OPTIONLENGTH(rdata);
    const uint8_t* option_data = _DNS_OffsetPtr<uint8_t>(rdata, 4);
    return std::vector<uint8_t>(option_data, option_data + option_length);
}

// ----------------

netpp::DNS_RData* RR_OPT_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    if (rdlength == 0) {
        return nullptr;
    }

    std::vector<netpp::DNS_RData_OPT::Option> options;
    options.reserve(4); // OPT RDATA typically contains a small number of options

    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);

    uint32_t rdata_offset = 0;
    while (rdata_offset < rdlength) {
        const DNSQuery_RDATA* option_ptr = _DNS_OffsetPtr<const DNSQuery_RDATA>(rdata, rdata_offset);
        const uint16_t option_code = DNSQuery_RDATA_GetOPT_OPTIONCODE(option_ptr);
        const uint16_t option_length = DNSQuery_RDATA_GetOPT_OPTIONLENGTH(option_ptr);

        if (rdata_offset + 4 + option_length > rdlength) {
            // Malformed OPT RDATA: option length exceeds remaining RDATA length
            fprintf(stderr, "Warning: Malformed OPT RDATA, option length exceeds remaining RDATA length. Stopping parsing.\n");
            break;
        }

        const std::vector<uint8_t> option_data = DNSQuery_RDATA_GetOPT_OPTIONDATA(option_ptr);
        options.emplace_back(netpp::DNS_RData_OPT::Option { static_cast<netpp::EDNSQuery_OPT_OptionCode>(option_code), option_data });

        rdata_offset += 4 + option_length; // Move to the next option (2 bytes for code, 2 bytes for length, followed by the option data)
    }

    return new netpp::DNS_RData_OPT(options);
}

uint16_t RR_OPT_Storer(netpp::DNS_StorerState& state, netpp::DNS_RData* rdata, netpp::EDNSQuery_RR_CLASS klass)
{
    netpp::DNS_RData_OPT* opt_rdata = static_cast<netpp::DNS_RData_OPT*>(rdata);

    uint16_t total_length = 0;
    for (const auto& option : opt_rdata->options()) {
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(option.code));
        DNSQuery_Push16(state.m_out, static_cast<uint16_t>(option.data.size()));
        state.m_out.insert(state.m_out.end(), option.data.begin(), option.data.end());
        total_length += 4 + static_cast<uint16_t>(option.data.size());
    }

    return total_length;
}

namespace netpp {

DNS_Record_OPT::DNS_Record_OPT(uint16_t udp_payload_size, uint8_t ext_rcode, uint8_t edns_version, bool dnssec_ok, uint16_t z, DNS_RData* data)
    : DNS_Record("", EDNSQuery_RR_TYPE::TYPE_OPT, (EDNSQuery_RR_CLASS)udp_payload_size, (uint32_t)((ext_rcode << 24) | (edns_version << 16) | (dnssec_ok ? 0x8000 : 0)), data)
{
    // data must be OPT RDATA, and data_length must be the length of the OPT RDATA
}

}
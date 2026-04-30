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
netpp::DNS_RData* RR_AAAA_Loader(const void* header, uint32_t rdlength, const void* rdata, netpp::EDNSQuery_RR_CLASS);

// --- Storers --- //
uint16_t RR_AAAA_Storer(std::vector<uint8_t>&, const void* header, netpp::DNS_RData*, netpp::EDNSQuery_RR_CLASS);

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

// ----------------

netpp::DNS_RData* RR_AAAA_Loader(const void* header_, uint32_t rdlength, const void* rdata_, netpp::EDNSQuery_RR_CLASS klass)
{
    const DNSQuery_RDATA* rdata = static_cast<const DNSQuery_RDATA*>(rdata_);
    const uint64_t upper = DNSQuery_RDATA_GetAAAA_ADDRESS_UPPER(rdata);
    const uint64_t lower = DNSQuery_RDATA_GetAAAA_ADDRESS_LOWER(rdata);
    return new netpp::DNS_RData_AAAA(upper, lower);
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
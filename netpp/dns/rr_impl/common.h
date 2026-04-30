// ------------------------------------
// The following code is based on
// the IETF RFC documentation
// ------------------------------------
// Authored by JoshuaMK
// ------------------------------------

#pragma once
 
#include <iostream>
#include <string>
#include <type_traits>

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

template <typename T, typename U>
inline auto _DNS_OffsetPtr(U* ptr, uint32_t ofs) -> std::conditional_t<std::is_const_v<U>, const T*, T*>
{
    // If U is const, byte_ptr will be const uint8_t*. Otherwise, uint8_t*.
    using byte_t = std::conditional_t<std::is_const_v<U>, const uint8_t, uint8_t>;

    if (!ptr)
        return nullptr;

    byte_t* byte_ptr = reinterpret_cast<byte_t*>(ptr);
    return byte_ptr + ofs;
}

inline uint16_t _DNS_ReadUnaligned16(const void* ptr)
{
    uint16_t val;
    std::memcpy(&val, ptr, sizeof(uint16_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

inline uint32_t _DNS_ReadUnaligned32(const void* ptr)
{
    uint32_t val;
    std::memcpy(&val, ptr, sizeof(uint32_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

inline uint64_t _DNS_ReadUnaligned64(const void* ptr)
{
    uint64_t val;
    std::memcpy(&val, ptr, sizeof(uint64_t));
    return NETPP_NETWORK_TO_SYSTEM_ENDIAN(val);
}

inline void _DNS_WriteUnaligned16(void* ptr, uint16_t val)
{
    uint16_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint16_t));
}

inline void _DNS_WriteUnaligned32(void* ptr, uint32_t val)
{
    uint32_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint32_t));
}

inline void _DNS_WriteUnaligned64(void* ptr, uint64_t val)
{
    uint64_t net_val = NETPP_SYSTEM_TO_NETWORK_ENDIAN(val);
    std::memcpy(ptr, &net_val, sizeof(uint64_t));
}

// ------------------------------------
// See: RFC1035 - 2.3.3.
// ------------------------------------
inline int DNS_StringCompareInsensitive(const std::string& l, const std::string& r)
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
inline std::string DNSQuery_GetDomainName(const DNSQuery_MessageHeader* h, const uint8_t* enc_data)
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

inline uint8_t DNSQuery_GetDomainNameCompressedSize(const uint8_t* enc_data)
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

inline uint8_t DNSQuery_GetDomainNameLength(const DNSQuery_MessageHeader* h, const uint8_t* enc_data)
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

inline std::string DNSQuery_GetCharacterString(const uint8_t* enc_data)
{
    const uint8_t token_length = (*enc_data & 0b11111111); // Is already <= DNS_NAME_OCTET_LIMIT due to the 1 byte length prefix
    return std::string((const char*)(enc_data + 1), token_length);
}

inline uint16_t DNSQuery_GetCharacterStringLength(const uint8_t* enc_data)
{
    return (uint16_t)(*enc_data) + 1;
}

// RFC 1035 - 4.1.2
struct DNSQuery_QuestionSection { };

// RFC 1035 - 4.1.3
struct DNSQuery_ResourceRecordSection { };

// RFC 1035
struct DNSQuery_RDATA { };

// -----------------
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
    using ret_t = std::conditional_t<std::is_const_v<U>, const T*, T*>;

    if (!ptr)
        return nullptr;

    byte_t* byte_ptr = reinterpret_cast<byte_t*>(ptr);
    return reinterpret_cast<ret_t>(byte_ptr + ofs);
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
        const bool is_extended = (enc_data[0] & 0b01000000) == 0b01000000;
        uint8_t token_value = (enc_data[0] & 0b00111111);

        if (is_compressed) {
            if (pointers_chased >= 10) {
                break; // We exit early to avoid malicious attacks
            }

            // token length and the next byte is the pointer offset in this case
            uint16_t pointer_offset = (token_value << 8) | (enc_data[1]);
            enc_data = (uint8_t*)h + pointer_offset;
            pointers_chased += 1;
            continue;
        }

        if (is_extended) {
            fprintf(stderr, "Warning: Extended label types are not supported, skipping label with value %d\n", token_value);
            enc_data += 1 + token_value; // Skip the extended label
            continue;
        }

        enc_data += 1;

        // NULL terminator
        if (token_value == 0) {
            break;
        }

        if (!result.empty()) {
            result.append(".");
        }

        result.append((const char*)enc_data, token_value);
        enc_data += token_value;
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

// Helper to write raw 16 bit integers to the back of the vector
inline void DNSQuery_Push16(std::vector<uint8_t>& out, uint16_t val)
{
    size_t offset = out.size();
    out.resize(out.size() + 2);
    _DNS_WriteUnaligned16(out.data() + offset, val);
}

// Helper to write raw 32 bit integers to the back of the vector
inline void DNSQuery_Push32(std::vector<uint8_t>& out, uint32_t val)
{
    size_t offset = out.size();
    out.resize(out.size() + 4);
    _DNS_WriteUnaligned32(out.data() + offset, val);
}

// Helper to write raw 64 bit integers to the back of the vector
inline void DNSQuery_Push64(std::vector<uint8_t>& out, uint64_t val)
{
    size_t offset = out.size();
    out.resize(out.size() + 8);
    _DNS_WriteUnaligned64(out.data() + offset, val);
}

    // Returns the index that comes directly after this domain name in the buffer
inline uint16_t DNSQuery_StoreDomainNameWithAdvance(netpp::DNS_StorerState& state, const std::string& dname, bool use_compression = true)
{
    const uint32_t start_len = static_cast<uint32_t>(state.m_out.size());
    
    if (dname.empty() || dname == ".") {
        state.m_out.push_back(0);
        return 1;
    }

    if (use_compression) {
        // In this case we store it as a compressed ptr
        if (state.m_dname_to_pointer_cache.find(dname) != state.m_dname_to_pointer_cache.end()) {
            const uint16_t pointer = state.m_dname_to_pointer_cache.at(dname);

            // DNS compression pointer: top 2 bits must be 11 (0xC000)
            const uint16_t compressed_ptr = 0xC000 | pointer;

            DNSQuery_Push16(state.m_out, compressed_ptr);
            return 2;
        }

        // Store as an uncompressed domain name and cache to the dname pointer map
        state.m_dname_to_pointer_cache[dname] = static_cast<uint16_t>(state.m_out.size() - state.m_header_idx);
    }

    // Parse the dname (Example: "www.google.com" -> \x03www\x06google\x03com\x00)
    size_t start = 0;
    while (start < dname.length()) {
        size_t end = dname.find('.', start);
        if (end == std::string::npos) {
            end = dname.length();
        }

        size_t len = end - start;
        if (len > 0) {
            state.m_out.push_back(static_cast<uint8_t>(len));
            for (size_t i = 0; i < len; ++i) {
                state.m_out.push_back(dname[start + i]);
            }
        }
        start = end + 1;
    }

    state.m_out.push_back(0); // NULL terminator
    return static_cast<uint16_t>(state.m_out.size() - start_len);
};

// -----------------
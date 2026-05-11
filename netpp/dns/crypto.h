#pragma once

#include <limits>
#include <string>
#include <vector>

#include "netpp.h"

namespace netpp {

// RFC4034 A.1
enum class EDNSSEC_ALGORITHM : uint8_t {
    ALGORITHM_RESERVED_0 = 0,
    ALGORITHM_RSAMD5 = 1, // RSA/MD5 (NOT RECOMMENDED)
    ALGORITHM_DH = 2, // Diffie-Hellman
    ALGORITHM_DSA = 3, // DSA/SHA-1
    ALGORITHM_ECC = 4, // Elliptic Curve
    ALGORITHM_RSASHA1 = 5, // RSA/SHA-1
    ALGORITHM_INDIRECT = 252,
    ALGORITHM_PRIVATEDNS = 253, // Reserved for private use, never assigned to a specific algorithm
    ALGORITHM_PRIVATEOID = 254, // Reserved for private use, never assigned to a specific algorithm
    ALGORITHM_RESERVED_255 = 255,
};

// RFC4034 A.2
enum class EDNSSEC_DIGESTTYPE : uint8_t {
    DIGEST_RESERVED_0 = 0,
    DIGEST_RESERVED_SHA1 = 1,
};

inline uint16_t DNSSEC_CreateKeyTag(const std::vector<uint8_t>& rr_key, EDNSSEC_ALGORITHM algorithm)
{
    // RFC4034 - B.1
    if (algorithm == EDNSSEC_ALGORITHM::ALGORITHM_RSAMD5) {
        // Grab the modulus from the public key in the RDATA
        if (rr_key.size() < 7) {
            fprintf(stderr, "Error: RSA/MD5 public key is too short to contain a valid modulus\n");
            return 0;
        }

        // The modulus is stored at -4 bytes from the end of the key.
        // To create the key tag, we take the middle 16 bits of the modulus, which starts at -3 and ends at -1
        const size_t key_tag_ofs = rr_key.size() - 3;

        const uint16_t key_tag = (rr_key[key_tag_ofs] << 8) | rr_key[key_tag_ofs + 1];
        return key_tag;
    }

    // RFC4034 A.2
    uint32_t ac = 0;
    for (size_t i = 0; i < rr_key.size(); ++i) {
        ac += (i & 1) ? rr_key[i] : rr_key[i] << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    return static_cast<uint16_t>(ac & 0xFFFF);
}

}
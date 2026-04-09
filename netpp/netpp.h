#pragma once

#include <functional>

#ifdef NETPP_STATIC
#define NETPP_API
#else
#ifdef NETPP_EXPORTS
#define NETPP_API __declspec(dllexport)
#else
#define NETPP_API __declspec(dllimport)
#endif
#endif

#define NETPP_BITWISE_ENUM(EnumType)                                                             \
    inline EnumType operator|(EnumType lhs, EnumType rhs) {                                        \
        using T = std::underlying_type_t<EnumType>;                                                \
        return static_cast<EnumType>(static_cast<T>(lhs) | static_cast<T>(rhs));                   \
    }                                                                                              \
    inline EnumType operator&(EnumType lhs, EnumType rhs) {                                        \
        using T = std::underlying_type_t<EnumType>;                                                \
        return static_cast<EnumType>(static_cast<T>(lhs) & static_cast<T>(rhs));                   \
    }                                                                                              \
    inline EnumType operator^(EnumType lhs, EnumType rhs) {                                        \
        using T = std::underlying_type_t<EnumType>;                                                \
        return static_cast<EnumType>(static_cast<T>(lhs) ^ static_cast<T>(rhs));                   \
    }                                                                                              \
    inline EnumType operator~(EnumType rhs) {                                                      \
        using T = std::underlying_type_t<EnumType>;                                                \
        return static_cast<EnumType>(~static_cast<T>(rhs));                                        \
    }                                                                                              \
    inline EnumType &operator|=(EnumType &lhs, EnumType rhs) {                                     \
        using T = std::underlying_type_t<EnumType>;                                                \
        lhs     = static_cast<EnumType>(static_cast<T>(lhs) | static_cast<T>(rhs));                \
        return lhs;                                                                                \
    }                                                                                              \
    inline EnumType &operator&=(EnumType &lhs, EnumType rhs) {                                     \
        using T = std::underlying_type_t<EnumType>;                                                \
        lhs     = static_cast<EnumType>(static_cast<T>(lhs) & static_cast<T>(rhs));                \
        return lhs;                                                                                \
    }                                                                                              \
    inline EnumType &operator^=(EnumType &lhs, EnumType rhs) {                                     \
        using T = std::underlying_type_t<EnumType>;                                                \
        lhs     = static_cast<EnumType>(static_cast<T>(lhs) ^ static_cast<T>(rhs));                \
        return lhs;                                                                                \
    }

namespace netpp {

    template <typename T>
    inline typename std::enable_if<std::is_arithmetic<T>::value, T>::type
    byteswap(T val)
    {
        union {
            T value;
            unsigned char bytes[sizeof(T)];
        } src = {}, dst = {};

        src.value = val;

        // Standard C++11 loop
        for (size_t i = 0; i < sizeof(T); i++) {
            dst.bytes[i] = src.bytes[sizeof(T) - 1 - i];
        }

        return dst.value;
    }

}
#define NETPP_BYTESWAP(val) netpp::byteswap((val))

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NETPP_NETWORK_TO_SYSTEM_ENDIAN(val) (val)
#define NETPP_SYSTEM_TO_NETWORK_ENDIAN(val) (val)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NETPP_NETWORK_TO_SYSTEM_ENDIAN(val) NETPP_BYTESWAP(val)
#define NETPP_SYSTEM_TO_NETWORK_ENDIAN(val) NETPP_BYTESWAP(val)
#elif defined(_WIN32) || defined(_WIN64)
#define NETPP_NETWORK_TO_SYSTEM_ENDIAN(val) NETPP_BYTESWAP(val)
#define NETPP_SYSTEM_TO_NETWORK_ENDIAN(val) NETPP_BYTESWAP(val)
#else
#define NETPP_NETWORK_TO_SYSTEM_ENDIAN(val) NETPP_BYTESWAP(val)
#define NETPP_SYSTEM_TO_NETWORK_ENDIAN(val) NETPP_BYTESWAP(val)
#endif
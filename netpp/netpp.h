#pragma once

#include <functional>

#ifdef NETPP_STATIC
#define NETPP_API
#else
#if defined(NETPP_SHARED) // OR defined(NETPP_EXPORTS)
#if defined(WIN32)
#if defined(NETPP_EXPORTS)
#define NETPP_API __declspec(dllexport)
#define NETPP_EXPIMP_T
#else
#define NETPP_API __declspec(dllimport)
#define NETPP_EXPIMP_T extern
#endif
#else
#define NETPP_API // Non-Windows doesn't need this usually
#define NETPP_EXPIMP_T
#endif
#else
#define NETPP_API // Static build, no declspec needed
#define NETPP_EXPIMP_T
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

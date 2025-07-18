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

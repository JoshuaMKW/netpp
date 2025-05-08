#pragma once

#ifdef NETPP_STATIC
#define NETPP_API
#else
#ifdef NETPP_EXPORTS
#define NETPP_API __declspec(dllexport)
#else
#define NETPP_API __declspec(dllimport)
#endif
#endif
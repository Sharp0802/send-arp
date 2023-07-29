#ifndef SEND_ARP_IP_H
#define SEND_ARP_IP_H

#include <cstdint>
#include <string>
#include <ifaddrs.h>
#include <optional>
#include <cstring>

#include "proxy.inl"
#include "convention.h"

#pragma pack(push, 1)
union RAW(IPv4)
{
	uint32_t i;
	uint8_t v[4];
};
#pragma pack(pop)

class IPv4 final
{
public:
	using Type = uint8_t;

	enum : Type
	{
		NONE,
		LOCAL,
		BROADCAST,
		MULTICAST
	};

private:
	RAW(IPv4) _v;

public:
	explicit IPv4(const std::string_view& view) : _v(0)
	{
		std::sscanf(view.data(), "%hhu.%hhu.%hhu.%hhu", &_v.v[0], &_v.v[1], &_v.v[2], &_v.v[3]);
	}

	explicit IPv4(const RAW(IPv4)& v) : _v(v)
	{
	}

	explicit IPv4(const RAW(IPv4)* v) : _v(*v)
	{
	}

	IPv4(const IPv4& rhs) : _v(rhs._v)
	{
	}

public:
	static std::optional<IPv4> self(const std::string_view& interface);

public:
	proxy_ro(IPv4, _v, Type) type = decl_proxy_ro(type, []decl_get(type)
	{
		if (__v->i == (uint32_t)-1)
			return BROADCAST;
		uint8_t prefix = __v->v[0];
		if (prefix == 0x7F)
			return LOCAL;
		if (0xE0 <= prefix && prefix < 0xF0)
			return MULTICAST;

		return NONE;
	});

	proxy_ro_redirect(IPv4, _v, value);

public:
	IPv4& operator=(const IPv4& rhs);

	bool operator==(const IPv4& rhs) const;

	explicit operator std::string() const;
};

#endif

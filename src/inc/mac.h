#ifndef SEND_ARP_MAC_H
#define SEND_ARP_MAC_H

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <optional>

#include "proxy.inl"
#include "convention.h"

#pragma pack(push, 1)
struct RAW(MAC)
{
	uint8_t v[6];
};
#pragma pack(pop)

class MAC final
{
public:
	using Type = uint64_t;

	enum : Type
	{
		NONE = 0x1,
		BLANK = 0x0,
		BROADCAST = 0x0000'FFFF'FFFF'FFFF,
		MULTICAST = 0x2
	};

private:
	union
	{
		uint64_t _h;
		struct
		{
			RAW(MAC) _v;
			PADDING(2);
		};
	};

public:
	explicit MAC(uint64_t h) : _h(h)
	{
		_h &= 0x0000FFFF'FFFFFFFF;
	}

	explicit MAC(const RAW(MAC)* v) : _v(*v)
	{
	}

	MAC(const MAC& rhs) : _h(rhs._h)
	{
		_h &= 0x0000FFFF'FFFFFFFF;
	}

	static std::optional<MAC> self(const std::string_view& interface);

public:
	bool operator_redirect(==, MAC, _h);
	bool operator_redirect(!=, MAC, _h);
	bool operator_redirect(<, MAC, _h);
	bool operator_redirect(<=, MAC, _h);
	bool operator_redirect(>, MAC, _h);
	bool operator_redirect(>=, MAC, _h);

	explicit operator std::string() const;

	MAC& operator =(const MAC& rhs);

public:
	proxy_ro(MAC, _h, Type) type = decl_proxy_ro(type, []decl_get(type)
	{
		if (*__v == 0)
			return BLANK;
		else if (*__v == 0x0000'FFFF'FFFF'FFFF)
			return BROADCAST;
		else if ((*__v & 0x0000'0000'80FF'FFFF) == 0x0000'0000'005E'0001)
			return MULTICAST;
		else
			return NONE;
	});

	proxy_ro_redirect(MAC, _v, value);
};

#endif

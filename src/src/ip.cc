#include "ip.h"
#include "log.inl"
#include <cstdio>

bool IPv4::operator==(const IPv4& rhs) const
{
	return rhs._v.i == _v.i;
}

IPv4& IPv4::operator=(const IPv4& rhs)
{
	_v.i = rhs._v.i;
	return *this;
}

IPv4::operator std::string() const
{
	std::array<char, 32> buf{};
	std::sprintf(buf.data(), "%u.%u.%u.%u", _v.v[0], _v.v[1], _v.v[2], _v.v[3]);
	return { buf.data() };
}

std::optional<IPv4> IPv4::self(const std::string_view& interface)
{
	ifaddrs* addr;
	auto r = getifaddrs(&addr);
	if (r) return std::nullopt;
	ifaddrs* taddr = addr;

	bool init = false;
	RAW(IPv4) raw{};
	do
	{
		if (interface == addr->ifa_name && static_cast<u_char>(addr->ifa_addr->sa_data[2]) == 192)
		{
			std::memcpy(raw.v, &addr->ifa_addr->sa_data[2], 4);
			init = true;
			break;
		}
		addr = addr->ifa_next;
	} while (addr->ifa_next);

	freeifaddrs(taddr);

	return init ? std::make_optional(IPv4(raw)) : std::nullopt;
}

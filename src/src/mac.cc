#include "mac.h"

MAC::operator std::string() const
{
	std::array<char, 20> buf{};
	std::sprintf(buf.data(), "%02X:%02X:%02X:%02X:%02X:%02X", _v.v[0], _v.v[1], _v.v[2], _v.v[3], _v.v[4], _v.v[5]);
	return { buf.data() };
}

std::optional<MAC> MAC::self(const std::string_view& interface)
{
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) return std::nullopt;

	struct ifreq ifr{};
	strcpy(ifr.ifr_name, interface.data());
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	RAW(MAC) mac{};
	std::memcpy(&mac, ifr.ifr_hwaddr.sa_data, 6);

	return std::make_optional(MAC(&mac));
}

MAC& MAC::operator=(const MAC& rhs)
{
	_h = rhs._h;
	return *this;
}

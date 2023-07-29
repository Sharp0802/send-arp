#ifndef SEND_ARP_ETHHDR_H
#define SEND_ARP_ETHHDR_H

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct RAW(ETH)
{
	RAW(MAC) dmac;
	RAW(MAC) smac;
	uint16_t type;
};
#pragma pack(pop)

class ETH final
{
public:
	using Type = uint16_t;

	enum : Type
	{
		IPv4 = 0x0800,
		ARP = 0x0806,
		IPv6 = 0x86DD
	};

private:
	const RAW(ETH) _v;

public:
	explicit ETH(const RAW(ETH)* v) : _v{ v->dmac, v->smac, ntohs(v->type) }
	{
	}

public:
	proxy_ro_member_redirect(ETH, _v, dmac, dmac);
	proxy_ro_member_redirect(ETH, _v, smac, smac);
	proxy_ro(ETH, _v, uint16_t) type = decl_proxy_ro(type, []decl_get(type) {
		// ethernet-type constants are already network-byte-order
		return __v->type; // ntohs(__v->type);
	});
};

#endif

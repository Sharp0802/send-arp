#ifndef SEND_ARP_ARPHDR_H
#define SEND_ARP_ARPHDR_H

#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#include "proxy.inl"
#include "convention.h"

#pragma pack(push, 1)
struct RAW(ARP) final
{
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;
	RAW(MAC) smac;
	RAW(IPv4) sip;
	RAW(MAC) dmac;
	RAW(IPv4) dip;
};
#pragma pack(pop)

class ARP final
{
public:
	using HardwareType = uint16_t;
	using ProtocolType = uint16_t;
	using OPCode = uint16_t;

	enum : HardwareType
	{
		NETROM = 0, // from KA9Q: NET/ROM pseudo
		ETHER = 1, // Ethernet 10Mbps
		EETHER = 2, // Experimental Ethernet
		AX25 = 3, // AX.25 Level 2
		PRONET = 4, // PROnet token ring
		CHAOS = 5, // Chaosnet
		IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
		ARCNET = 7, // ARCnet
		APPLETLK = 8, // APPLEtalk
		LANSTAR = 9, // Lanstar
		DLCI = 15, // Frame Relay DLCI
		ATM = 19, // ATM
		METRICOM = 23, // Metricom STRIP (new IANA id)
		IPSEC = 31 // IPsec tunnel
	};

	enum : ProtocolType
	{
		IPv4 = 0x0800
	};

	enum : OPCode
	{
		Request = 1, // req to resolve address
		Reply = 2, // resp to previous request
		RevRequest = 3, // req protocol address given hardware
		RevReply = 4, // resp giving protocol address
		InvRequest = 8, // req to identify peer
		InvReply = 9 // resp identifying peer
	};

private:
	const RAW(ARP) _v;

public:
	explicit ARP(const RAW(ARP)* r) : _v(*r)
	{
	}

	ARP(const ARP& rhs) : _v(rhs._v)
	{
	}

public:
	proxy_ro(ARP, _v, decltype(decltype(_v)::hrd)) hrd = decl_proxy_ro(hrd, []decl_get(hrd) {
		return ntohs(__v->hrd);
	});
	proxy_ro(ARP, _v, decltype(decltype(_v)::pro)) pro = decl_proxy_ro(pro, []decl_get(pro){
		return ntohs(__v->pro);
	});
	proxy_ro_member_redirect(ARP, _v, hln, hln);
	proxy_ro_member_redirect(ARP, _v, pln, pln);
	proxy_ro(ARP, _v, decltype(decltype(_v)::op)) op = decl_proxy_ro(op, []decl_get(op){
		return ntohs(__v->op);
	});
	proxy_ro_member_redirect(ARP, _v, smac, smac);
	proxy_ro_member_redirect(ARP, _v, sip, sip);
	proxy_ro_member_redirect(ARP, _v, dmac, dmac);
	proxy_ro_member_redirect(ARP, _v, dip, dip);
};

#endif

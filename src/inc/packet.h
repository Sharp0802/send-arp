#ifndef SEND_ARP_PACKET_H
#define SEND_ARP_PACKET_H

#include <memory>
#include <optional>
#include <utility>
#include <pcap/pcap.h>

#include "ethhdr.h"
#include "arphdr.h"

#include "thread"
#include "future"

#include "convention.h"
#include "proxy.inl"

#pragma pack(push, 1)
struct RAW(PACKET) final
{
	RAW(ETH) eth;
	RAW(ARP) arp;
};
#pragma pack(pop)

class PACKET final
{
private:
	std::shared_ptr<pcap_t> _pcap;
	RAW(PACKET) _raw;

private:
	void initial()
	{
		_raw.eth.type = htons(ETH::ARP);
		_raw.arp.hrd = htons(ARP::ETHER);
		_raw.arp.pro = htons(ARP::IPv4);
		_raw.arp.hln = 6;
		_raw.arp.pln = 4;
	}

public:
	explicit PACKET(std::shared_ptr<pcap_t> pcap) : _pcap(std::move(pcap))
	{
		std::memset(&_raw, 0, sizeof(_raw));
		initial();
	}

	explicit PACKET(std::shared_ptr<pcap_t> pcap, const RAW(PACKET)& packet) : _pcap(std::move(pcap)), _raw(packet)
	{
		initial();
	}

	explicit PACKET(std::shared_ptr<pcap_t> pcap, const RAW(PACKET)* packet) : _pcap(std::move(pcap)), _raw(*packet)
	{
		initial();
	}

public:
	bool send();
	std::future<std::optional<PACKET>> send_async();

public:
	proxy_rw(PACKET, _raw, IPv4) dip = decl_proxy_rw(dip,
			[]decl_get(dip) {
		return IPv4(&__v->arp.dip);
	},
			[]decl_set(dip) {
		RAW(IPv4) v = __p.value.get();
		__v->arp.dip = v;
		return __p;
	});

	proxy_rw(PACKET, _raw, MAC) dmac = decl_proxy_rw(dmac,
			[]decl_get(dmac) {
		return MAC(&__v->arp.dmac);
	},
			[]decl_set(dmac) {
		RAW(MAC) v = __p.value.get();
		__v->arp.dmac = __p.type.get() == MAC::BROADCAST ? MAC(MAC::BLANK).value.get() : v;
		__v->eth.dmac = v;
		return __p;
	});

	proxy_rw(PACKET, _raw, IPv4) sip = decl_proxy_rw(dip,
			[]decl_get(dip) {
		return IPv4(&__v->arp.sip);
	},
			[]decl_set(dip) {
		RAW(IPv4) v = __p.value.get();
		__v->arp.sip = v;
		return __p;
	});

	proxy_rw(PACKET, _raw, MAC) smac = decl_proxy_rw(smac,
			[]decl_get(smac) {
		return MAC(&__v->arp.smac);
	},
			[]decl_set(smac) {
		RAW(MAC) v = __p.value.get();
		std::memcpy(&__v->arp.smac, &v, 6);
		std::memcpy(&__v->eth.smac, &v, 6);
		return __p;
	});

	proxy_rw(PACKET, _raw, ARP::OPCode) op = decl_proxy_rw(op,
			[]decl_get(op) {
		return ntohs(__v->arp.op);
	},
			[]decl_set(op) {
		__v->arp.op = htons(__p);
		return __p;
	});
};

#endif //SEND_ARP_PACKET_H

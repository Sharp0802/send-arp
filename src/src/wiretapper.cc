#include "wiretapper.h"
#include "log.inl"
#include "ethhdr.h"
#include "packet.h"
#include <mutex>

uint64_t wiretapper::operator+=(const handler& fn)
{
	auto fid = __sync_add_and_fetch(&_fid, 1);
	_handler.emplace_back(fid, fn);
	return fid;
}

void wiretapper::operator-=(uint64_t fid)
{
	std::erase_if(_handler, [fid](std::tuple<uint64_t, handler> tuple)
	{
		return get<0>(tuple) == fid;
	});
}

void wiretapper::run(const volatile bool* token)
{
	LOG(INFO) << "wiretapper started";
	while (*token)
	{
		struct pcap_pkthdr* hdr;
		const u_char* data;
		auto r = pcap_next_ex(_pcap.get(), &hdr, &data);
		switch (r)
		{
		case 0:
			break;
		case PCAP_ERROR:
		case PCAP_ERROR_BREAK:
			LOG(WARN) << "pcap_next_ex return " << r << '(' << pcap_geterr(_pcap.get()) << ')';
			goto HARD_BREAK;
		default:
			if (hdr->caplen < sizeof(RAW(PACKET)))
				break;
			ETH eth(reinterpret_cast<const RAW(ETH)*>(data));
			LOG(INFO) << "ETH received (" << hdr->caplen << " bytes, op:" << std::hex << eth.type.get() << std::dec << ')';
			if (eth.type.get() != ETH::ARP)
				break;

			PACKET packet(_pcap, reinterpret_cast<const RAW(PACKET)*>(data));
			LOG(INFO) << "ARP received (" << static_cast<std::string>(packet.smac.get()) << " >> " << static_cast<std::string>(packet.dmac.get()) << ')';
			for (const auto& handler : _handler)
				get<1>(handler)(packet);
			break;
		}
	}
	HARD_BREAK:
}

void wiretapper::boot()
{
	std::lock_guard<std::mutex> lock(_sync);

	if (_worker)
	{
		_token = false;
		_worker->join();
	}

	_token = true;
	_worker = std::make_unique<std::thread>(&wiretapper::run, this, &_token);
}

void wiretapper::stop()
{
	std::lock_guard<std::mutex> lock(_sync);

	_token = false;
	if (_worker)
		_worker->join();
	_worker = nullptr;
}

wiretapper::~wiretapper()
{
	stop();
}

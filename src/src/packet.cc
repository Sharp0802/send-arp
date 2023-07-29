#include "packet.h"
#include "wiretapper.h"
#include "spinlock.h"
#include "log.inl"

bool PACKET::send()
{
	auto r = pcap_sendpacket(_pcap.get(), reinterpret_cast<const u_char*>(&_raw), sizeof(_raw));
	if (r) LOG(FAIL) << "could not send packet with pcap";
	return !r;
}

std::future<std::optional<PACKET>> PACKET::send_async()
{
	return std::async(std::launch::async, [*this]() -> std::optional<PACKET>
	{
		spinlock lock{};
		lock.lock();

		RAW(PACKET) raw{};

		auto fid = std::make_unique<uint64_t>();
		*fid = wiretapper::instance() += [&fid, &lock, &raw, this](const PACKET& packet) {
			if (dmac.get().type.get() != MAC::BLANK &&
				dmac.get() != packet.smac.get())
				return;
			if (smac.get() != packet.dmac.get())
				return;

			raw = packet._raw;

			// clean-up
			lock.unlock();
			wiretapper::instance() -= *fid;
		};

		LOG(INFO) << "sending packet... (" << sizeof(_raw) << " bytes writing)";
		auto r = pcap_inject(_pcap.get(), reinterpret_cast<const u_char*>(&_raw), sizeof(_raw));
		if (r == 0)
		{
			LOG(FAIL) << "could not send packet with pcap";

			// clean-up
			lock.unlock();
			wiretapper::instance() -= *fid;

			return std::nullopt;
		}

		LOG(INFO) << "waiting response... (" << r << " bytes written)";
		lock.lock(); // wait
		lock.unlock();

		return std::make_optional(PACKET(_pcap, raw));
	});
}

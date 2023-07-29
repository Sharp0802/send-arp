#ifndef SEND_ARP_WIRETAPPER_H
#define SEND_ARP_WIRETAPPER_H

#include <functional>
#include <thread>
#include <utility>
#include <vector>
#include <memory>
#include <pcap/pcap.h>
#include "packet.h"

class wiretapper final
{
private:
	using handler = std::function<void(const PACKET&)>;

private:
	const std::shared_ptr<pcap_t> _pcap;
	volatile uint64_t _fid;
	std::vector<std::tuple<uint64_t, handler>> _handler;
	std::unique_ptr<std::thread> _worker;
	std::mutex _sync;
	bool _token;

public:
	explicit wiretapper(std::shared_ptr<pcap_t> pcap) :
		_pcap(std::move(pcap)),
		_fid(0),
		_handler(),
		_worker(nullptr),
		_token(false)
	{
		_instance = this;
	}

	~wiretapper();

private:
	inline static wiretapper* _instance;

public:
	static wiretapper& instance()
	{
		return *_instance;
	}

public:
	uint64_t operator+=(const handler& fn);

	void operator-=(uint64_t fid);

private:
	void run(const volatile bool* token);

public:
	void boot();

	void stop();
};

#endif //SEND_ARP_WIRETAPPER_H

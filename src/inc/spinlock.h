#ifndef SEND_ARP_SPINLOCK_H
#define SEND_ARP_SPINLOCK_H

#include <atomic>

class spinlock final
{
private:
	std::atomic<bool> _sync = { false };

public:
	void lock()
	{
		for (;;)
		{
			if (!_sync.exchange(true, std::memory_order_acquire))
				return;
			while (_sync.load(std::memory_order_relaxed))
				__builtin_ia32_pause();
		}
	}

	bool try_lock()
	{
		return !_sync.load(std::memory_order_relaxed) &&
			   !_sync.exchange(true, std::memory_order_acquire);
	}

	void unlock()
	{
		_sync.store(false, std::memory_order_release);
	}
};


#endif //SEND_ARP_SPINLOCK_H

#ifndef SEND_ARP_FW_H
#define SEND_ARP_FW_H

#define ____CONCAT(a, b) a##b
#define ___CONCAT(a, b) ____CONCAT(a, b)

#define RAW(symbol) ___RAW__##symbol
#define UNUSED(size) uint8_t ___CONCAT(___dummy__, __COUNTER__)[size] = {0, }
#define PADDING(size) UNUSED(size)

#define operator_redirect(op, type, field) operator op (const type & rhs) { return rhs . field op field ; }

#define integral_swap(v, a, b) { v[a] ^= v[b]; v[b] ^= v[a]; v[a] ^= v[b]; }

constexpr uint64_t ntohll(uint64_t v)
{
	union
	{
		uint8_t i8[8];
		uint64_t i64;
	} u;
	u.i64 = v;
	integral_swap(u.i8, 7, 0);
	integral_swap(u.i8, 6, 1);
	integral_swap(u.i8, 5, 2);
	integral_swap(u.i8, 4, 3);
	return u.i64;
}

#define htonll ntohll

#endif //SEND_ARP_FW_H

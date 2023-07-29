#ifndef SEND_ARP_FORWARD_H
#define SEND_ARP_FORWARD_H

#include <sys/types.h>
#include <functional>
#include <cstddef>

template<
		typename C,
		typename F,
		typename P,
		F C::*member>
class __proxy_rw final
{
public:
	using field_t = F;
	using proxy_t = P;

private:
	F* _ptr;
	const std::function<P(F* field)> _getter;
	const std::function<P(const P& value, F* field)> _setter;

public:
	explicit __proxy_rw(
			const C* container,
			std::function<P(F* field)> getter,
			std::function<P(const P& value, F* field)> setter)
			: _ptr(&(const_cast<C*>(container)->*member)), _getter(getter), _setter(setter)
	{
	}

public:
	P get() const
	{
		return _getter(_ptr);
	}

	P set(const P& value)
	{
		return _setter.operator()(value, _ptr);
	}
};

template<
		typename C,
		typename F,
		typename P,
		F C::*member>
class __proxy_ro final
{
public:
	using field_t = F;
	using proxy_t = P;

private:
	const F* _ptr;
	const std::function<P(const F* field)> _getter;

public:
	explicit __proxy_ro(
			const C* container,
			std::function<P(const F* field)> getter)
			: _ptr(&(container->*member)), _getter(getter)
	{
	}

public:
	P get() const
	{
		return _getter(_ptr);
	}
};

#define proxy_rw(c, f, t) __proxy_rw<c, decltype(f), t, &c::f>
#define proxy_ro(c, f, t) const __proxy_ro<c, decltype(f), t, &c::f>

#define decl_get(p)                    (const decltype(p)::field_t* __v)
#define decl_get_redirect(p)           [](const decltype(p)::field_t* __v) { return *__v; }
#define decl_get_member_redirect(p, m) [](const decltype(p)::field_t* __v) { return __v-> m ; }
#define decl_set(p)                    (const decltype(p)::proxy_t& __p, decltype(p)::field_t* __v)

#define decl_proxy_ro(p, c)    decltype(p)((this), c)
#define decl_proxy_rw(p, c, s) decltype(p)((this), c, s)

#define proxy_ro_redirect(c, f, n)           proxy_ro(c, f, decltype(f)) n = decl_proxy_ro(n, decl_get_redirect(n))
#define proxy_ro_member_redirect(c, f, m, n) proxy_ro(c, f, decltype(decltype(f)::m)) n = decl_proxy_ro(n, decl_get_member_redirect(n, m))

#endif //SEND_ARP_FORWARD_H

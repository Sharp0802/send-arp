#ifndef SEND_ARP_LOG_INL
#define SEND_ARP_LOG_INL

#include <array>
#include <cstring>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <spinlock.h>

#define FAIL "\033[1;31mfail\033[0m"
#define WARN "\033[1;33mwarn\033[0m"
#define INFO "\033[1;39minfo\033[0m"
#define NOTE "\033[1;36mnote\033[0m"
#define VERB "\033[1;90mverb\033[0m"

namespace logging
{
	template<char... str>
	struct char_seq
	{
		static constexpr const char data[] = { str..., 0 };
	};

	class msg_ctx
	{
	private:
		std::basic_ostream<char>& _out;
		std::stringstream _buf;

	public:
		explicit msg_ctx(std::basic_ostream<char>& out) : _out(out), _buf()
		{
		}

		~msg_ctx()
		{
			_out << _buf.str() << std::endl;
		}

	public:
		template<typename T>
		msg_ctx& operator<<(const T& arg)
		{
			_buf << arg;
			return *this;
		}
	};

	template<typename...>
	class ctx_head;

	template<char... file, char... line, char... head>
	class ctx_head<char_seq<file...>, char_seq<line...>, char_seq<head...>>
	{
	private:
		static constexpr std::basic_ostream<char>& buf()
		{
			if (std::strcmp(char_seq<head...>::data, FAIL) == 0)
				return std::cerr;
			else
				return std::cout;
		}

		static constexpr auto header()
		{
			return std::format("{}:{}: {}: ",
					char_seq<file...>::data,
					char_seq<line...>::data,
					char_seq<head...>::data);
		}

	public:
		static msg_ctx init()
		{
			std::basic_ostream<char>& out = buf();
			out << header();
			return msg_ctx(out);
		}
	};
}

template<typename T, T... str>
consteval logging::char_seq<str...> operator ""_seq()
{
	return {};
}

#define __STR(a) #a
#define _STR(a) __STR(a)
#define __TSTR(a) a##_seq
#define _TSTR(a) decltype(__TSTR(a))
#define LOG(head) logging::ctx_head<_TSTR(__FILE_NAME__), _TSTR(_STR(__LINE__)), _TSTR(head)>::init()

#endif //SEND_ARP_LOG_INL
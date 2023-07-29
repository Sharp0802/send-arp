#ifndef SEND_ARP_FW_H
#define SEND_ARP_FW_H

#define ____CONCAT(a, b) a##b
#define ___CONCAT(a, b) ____CONCAT(a, b)

#define RAW(symbol) ___RAW__##symbol
#define UNUSED(size) uint8_t ___CONCAT(___dummy__, __COUNTER__)[size] = {0, }
#define PADDING(size) UNUSED(size)

#define operator_redirect(op, type, field) operator op (const type & rhs) { return rhs . field op field ; }

#endif //SEND_ARP_FW_H

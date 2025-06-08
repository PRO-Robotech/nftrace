#ifndef __COMMON_H__
#define __COMMON_H__

struct ip4_tuple
{
    u16 src_port;
    u16 dst_port;
    u32 src_ip;
    u32 dst_ip;
    u8 ip_proto;
};

struct ip6_tuple
{
    u16 src_port;
    u16 dst_port;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
    u8 ip_proto;
};

#endif

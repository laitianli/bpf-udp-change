#ifndef __BPF_CHANGE_PORT_H_
#define __BPF_CHANGE_PORT_H_
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
	//#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define __my_htons ___constant_swab16

typedef unsigned long long u64;
typedef long long s64;
typedef __u32 u32;
typedef __s32 s32;

typedef __u16 u16;
typedef __s16 s16;

typedef __u8  u8;
typedef __s8  s8;

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#if 1
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;

 #define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline)
#endif

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define GTPU_HEAD_LEN 8

#define UDP_LOCAL_PORT 7788
#define UDP_PROXY_PORT 9000

static __always_inline int ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & __my_htons(IP_MF | IP_OFFSET)) != 0;
}


static /*__always_inline*/ int bpf_cp_parse_ipv4(u8 *data, u16* nh_off, u8 *data_end, u8* should_recheck)
{
	struct iphdr *iph = (struct iphdr *)(data + *nh_off);

	if ((u8*)(iph + 1) > data_end)
		return 0;
	*nh_off += iph->ihl << 2;
	*should_recheck = ip_is_fragment(iph);
	//bpf_printk("iph->protocol: %d\n", iph->protocol);
	return iph->protocol;
}

static /*__always_inline*/ int bpf_cp_parse_ipv6(u8 *data, u16* nh_off, u8 *data_end)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + *nh_off);

	if ((u8*)(ip6h + 1) > data_end)
		return 0;
	*nh_off += sizeof(struct ipv6hdr);
	return ip6h->nexthdr;
}

#endif


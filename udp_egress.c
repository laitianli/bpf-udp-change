#include "bpf_udp_change.h"

static __always_inline __be16 bpf_cp_get_udp_new_check(__be16 udp_check)
{
	u32 check = (u32)udp_check;
	if (UDP_LOCAL_PORT > UDP_PROXY_PORT)
		check += (u32)((UDP_LOCAL_PORT - UDP_PROXY_PORT) << 8);
	else if (UDP_LOCAL_PORT < UDP_PROXY_PORT)
		check += (u32)((UDP_PROXY_PORT - UDP_LOCAL_PORT) << 8);

	if (udp_check != check)
		udp_check = (__u16)(check + (check >= 0xFFFF));
	return udp_check;
}


static __always_inline void bpf_cp_change_udp_port_egress(u8 *data, u16 nh_off, u8 *data_end, u8 should_recheck)
{
	if ((u8*)(data + nh_off) > data_end)
		return;

	struct udphdr* uh = (struct udphdr*)(data + nh_off);
	
	if ((u8*)uh + sizeof(struct udphdr) <= data_end){
		if (uh->source == __my_htons(UDP_LOCAL_PORT)) {
			uh->source = __my_htons(UDP_PROXY_PORT);
			
			if (should_recheck) {
				uh->check = bpf_cp_get_udp_new_check(uh->check);
			}			
		}
	}
}

static __always_inline int do_change_udp_port(u8 *data, u8 *data_end) 
{
	struct ethhdr *eth = (struct ethhdr *)data;
	int rc = TC_ACT_OK;
	u16 h_proto;
	u16 nh_off;
	u32 ipproto;
	u8 should_recheck = 0;
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;
	if (h_proto == __my_htons(ETH_P_8021Q) || h_proto == __my_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = (struct vlan_hdr *)(data + nh_off);
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == __my_htons(ETH_P_8021Q) || h_proto == __my_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = (struct vlan_hdr *)(data + nh_off);
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == __my_htons(ETH_P_IP)) {
		ipproto = bpf_cp_parse_ipv4(data, &nh_off, data_end, &should_recheck);
	}
	else if (h_proto == __my_htons(ETH_P_IPV6)) {
		ipproto = bpf_cp_parse_ipv6(data, &nh_off, data_end);
	}
	else
		ipproto = 0;
	if (data + nh_off > data_end)
		return rc;
	if (ipproto == IPPROTO_UDP) {
		bpf_cp_change_udp_port_egress(data, nh_off, data_end, should_recheck);
		rc = TC_ACT_OK;
	}
	return rc;
}

SEC("tc_udp_egress")
int tc_egress_func(struct __sk_buff *skb)
{
    return do_change_udp_port((u8 *)(long)skb->data, (u8 *)(long)skb->data_end);
}


char _license[] SEC("license") = "GPL";


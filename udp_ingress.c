#include "bpf_udp_change.h"

static __always_inline void bpf_cp_change_udp_port_ingress(u8 *data, u16 nh_off, u8 *data_end)
{
	if ((u8*)(data + nh_off) > data_end)
		return ;

	struct udphdr* uh = (struct udphdr*)(data + nh_off);
	if ((u8*)uh + sizeof(struct udphdr) <= data_end) {
		if (__my_htons(UDP_PROXY_PORT) == uh->dest) {
			uh->dest = __my_htons(UDP_LOCAL_PORT);
			uh->check = 0;
		}
	}
}

static __always_inline int do_change_udp_port_ingress(u8 *data, u8 *data_end) 
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
	//bpf_printk("h_proto: 0x%x\n", h_proto); //ok
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
	else {
		//bpf_printk("h_proto: 0x%x\n", __my_htons(h_proto));
		ipproto = 0;
	}

	if (data + nh_off > data_end)
		return rc;
	
	if (ipproto == IPPROTO_UDP) {
		bpf_printk("[do_change_udp_port_ingress:%d] ipproto: %d\n", __LINE__, ipproto);
		bpf_cp_change_udp_port_ingress(data, nh_off, data_end);
		rc = TC_ACT_OK;
	}
	return rc;
}

SEC("tc_udp_ingress")
int tc_ingress_func(struct __sk_buff *skb) 
{
    return do_change_udp_port_ingress((u8 *)(long)skb->data, (u8 *)(long)skb->data_end);
}

char _license[] SEC("license") = "GPL";


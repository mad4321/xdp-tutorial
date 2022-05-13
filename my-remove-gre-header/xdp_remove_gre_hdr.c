/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdint.h>

#include "../common/parsing_helpers.h"

struct grehdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint16_t rec:3,
	     ssr:1,
	     seq:1,
	     key:1,
	     rb:1,
	     csb:1,
	     version:3,
	     flags:5;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint16_t csb:1,
	     rb:1,
	     key:1,
	     seq:1,
	     ssr:1,
	     rec:3,
	     flags:5,
	     version:3;
#endif
    uint16_t protocol;
};

static __always_inline int parse_grehdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct grehdr **grehdr)
{
	struct grehdr *greh = nh->pos;

	if (greh + 1 > data_end)
		return -1;

	nh->pos  = greh + 1;
	*grehdr = greh;

	return greh->protocol;
}

SEC("xdp")
int  xdp_prog_remove_gre_hdr(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	int ip_type;
	int eth_type;
	int gre_type;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	struct grehdr *gre;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type == IPPROTO_GRE) {
			gre_type = parse_grehdr(&nh, data_end, &gre);
			if (gre_type == bpf_htons(0x88be)) {
				bpf_xdp_adjust_head(ctx, 38);
			}
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

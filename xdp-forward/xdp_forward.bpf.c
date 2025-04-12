// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define AF_INET	2
#define AF_INET6	10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)

struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params,
	__u32 params__sz, int *err) __ksym;
struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

struct connection
{
	struct bpf_crypto_ctx __kptr * ctx;
};

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, __u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;
		if (iph->protocol == IPPROTO_IPIP) { // unlikely，客户端上行是少的
			// todo 根据外层IP决定使用哪个加密隧道出去
			struct iphdr *inner_ip = iph + 1;
			if (inner_ip + 1 > data_end) {
				return XDP_DROP;
			}

			// 按封包格式加密直接网卡丢回去
			return XDP_TX;
		}

		if (iph->protocol == IPPROTO_TCP) { // 加密隧道是TCP
			// 服务器端，unlikely，如果是传入端口，转发到用户态AF_XDP处理
			// 客户端，收到的是握手回复的话，转发到用户态AF_XDP处理

			// 路由器通过IPIP ICMP ping 加密隧道对端时，应该期待ICMP也从IPIP隧道返回。
			// 其他情况下，不走IPIP隧道直接回给局域网

			// 查询是否隧道下行包
			// 1. 封包解密

			// 2. 重置为内层隧道的类型，查找邻居，直接转发
			iph = iph + 1;
			h_proto = bpf_htons(ETH_P_IP);
		} else {
			// 不是上行，也不是下行流量，不管
			return XDP_PASS;
		}
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		// todo 支持上行IPv6 封装
		// if (ip6h->nexthdr == IPPROTO_IPV6) {
		// }

		if (ip6h->nexthdr == IPPROTO_TCP) {

		} else {
			return XDP_PASS;
		}
	} else {
		return XDP_PASS;
	}

	// 到这里是下行隧道的转发了
	// 由于nat放到了隧道对端去做，这里的ipv4/ipv6 dst都已经是局域网了
	if (h_proto == bpf_htons(ETH_P_IP)) {
		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;
		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		// 隧道内没有IP协议外的协议
		return XDP_DROP;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	/*
	 * Some rc (return codes) from bpf_fib_lookup() are important,
	 * to understand how this XDP-prog interacts with network stack.
	 *
	 * BPF_FIB_LKUP_RET_NO_NEIGH:
	 *  Even if route lookup was a success, then the MAC-addresses are also
	 *  needed.  This is obtained from arp/neighbour table, but if table is
	 *  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
	 *  doing ARP lookup directly from XDP, then send packet to normal
	 *  network stack via XDP_PASS and expect it will do ARP resolution.
	 *
	 * BPF_FIB_LKUP_RET_FWD_DISABLED:
	 *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
	 *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
	 *  enabled this on ingress device.
	 */
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Verify egress index has been configured as TX-port.
		 * (Note: User can still have inserted an egress ifindex that
		 * doesn't support XDP xmit, which will result in packet drops).
		 *
		 * Note: lookup in devmap supported since 0cdbb4b09a0.
		 * If not supported will fail with:
		 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 */
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS; // 上面注释说如果邻居表ARP为空，需要PASS上去做ARP解析

		// 不递减ttl了
		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect_map(&xdp_tx_ports, fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_fwd_fib_full(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, 0);
}

SEC("xdp")
int xdp_fwd_fib_direct(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

struct tunnel_args {
    int prog_fd;
    unsigned int hid;
    int retval;

	char cipher[128];
	__u8 key[256];
};

SEC("syscall")
int set_tunnel(struct tunnel_args *args)
{
	// 修改map
	struct bpf_crypto_ctx *cctx;
    struct bpf_crypto_params params = {
        .type = "skcipher",
        .key_len = 1,
        .authsize = 1,
    };
	int err = 0;

	struct bpf_crypto_ctx *cctx;
	__builtin_memcpy(&params.algo, args->cipher, sizeof(args->cipher));
    __builtin_memcpy(&params.key, args->key, sizeof(args->key));
    cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!cctx) {
		return err;
	}

	(void)cctx;

    return 0;
}

char _license[] SEC("license") = "GPL";

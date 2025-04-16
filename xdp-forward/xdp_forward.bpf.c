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

#define SERVER 1
#define CLIENT 1

struct bpf_crypto_params {
	char type[14];
	__u8 reserved[2];
	char algo[128];
	__u8 key[256];
	__u32 key_len;
	__u32 authsize;
};

struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params,
	__u32 params__sz, int *err) __ksym;
struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;

int netif_rx(struct sk_buff *skb) __ksym;

struct conn_tuple {
	__u16 local_port;
	__u16 remote_port;
	struct in6_addr local;
	struct in6_addr remote;
};

struct connection {
	union {
		struct {
			__u64 xsk_index;
		} handshake_conn;

		struct {
			__u32 seq;
			__u32 ack_seq;
			__u32 window;
			__u32 peer_window;

			__u8 state;

			struct bpf_crypto_ctx __kptr * ctx;
		} data_conn;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 8);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, struct conn_tuple);
	__type(value, struct connection);
} conn_maps SEC(".maps");

static inline struct in6_addr ipv4_mapped(__be32 ipv4) {
	return (struct in6_addr){.s6_addr32 = {0, 0, 0xffff, ipv4}};
}

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, __u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	int rc;

	if (eth + 1 > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = (void*)(eth + 1);

		if (iph + 1 > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;
#ifdef CLIENT
		if (iph->protocol == IPPROTO_IPIP) { // unlikely，客户端上行是少的
			// todo 根据外层IP决定使用哪个加密隧道出去
			struct iphdr *inner_ip = iph + 1;
			if (inner_ip + 1 > data_end) {
				return XDP_DROP;
			}

			// 按封包格式加密直接网卡丢回去
			// 按IPv4/IPv6+额外字段修改空间
			if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr))) {
				return XDP_DROP;
			}
			data_end = (void *)(long)ctx->data_end;
			data = (void *)(long)ctx->data;

			// set_eth, 这里用固定的还是一样fib呢？
			// 修复校验和

			return XDP_TX;
		}
#endif // CLIENT

		struct conn_tuple key = {
			.local = ipv4_mapped(iph->daddr),
			.remote = ipv4_mapped(iph->saddr),
		};

		// 如果是ICMP先把内层tcp解析出来，然后查找对应的tcp或者udp
		if (iph->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (void*)(iph + 1);
			if (icmp + 1 > data_end) {
				return XDP_DROP;
			}
			if (icmp->type == 0) {
				return XDP_PASS;
			}
			struct iphdr *next_iph = (void*)(icmp + 1);
			if ((void*)(next_iph + 1) + 8 < data_end) {
				// 不是错误包
				return XDP_PASS;
			}
			// 除了ip头外至少要有8个字节
			if (next_iph->protocol == IPPROTO_TCP) {
				struct tcphdr *next_tcph = (void*)(next_iph + 1);
				key.local_port = next_tcph->dest;
				key.remote_port = next_tcph->source;
				key.local = ipv4_mapped(next_iph->saddr);
				key.remote = ipv4_mapped(next_iph->daddr);
				goto lookup_tcp_conn;
			}
			return XDP_PASS;
		}

		if (iph->protocol == IPPROTO_TCP) { // 加密隧道是TCP
			struct tcphdr* tcp = (void*)(iph + 1);
			struct connection *data_conn;
			if (tcp + 1 > data_end) {
				return XDP_DROP;
			}

			key.local_port = tcp->dest;
			key.remote_port = tcp->source;
lookup_tcp_conn:
			data_conn = bpf_map_lookup_elem(&conn_maps, &key);
#ifdef SERVER
			// 服务器端
			// likely
			if (data_conn) {
				// 隧道数据, 转发给einat_ebpf 合并nat处理？
				// todo 如果本节点是中继，传给下个节点的话
				return XDP_PASS;
			}

			// unlikely 如果是传入端口，转发到用户态AF_XDP处理
			key.local_port = 0;
			__builtin_memset(&key.local.s6_addr32, 0, sizeof(struct in6_addr));
			data_conn = bpf_map_lookup_elem(&conn_maps, &key);
			if (data_conn) {
				// 做下mac的检查，通过才放到用户态
				return bpf_redirect_map(&xsks_map, data_conn->handshake_conn.xsk_index, 0);
			}
			// 可能最终是要进隧道的, 想办法转发给einat_ebpf找到目标的ip和tcp，然后改写ip直接加密进隧道
			return XDP_PASS;
#endif // SERVER
#ifdef CLIENT
			// 客户端。不做nat
			if (data_conn) {
				switch (data_conn->data_conn.state)
				{
				case 0:
					return XDP_TX;
				default:
					return XDP_DROP;
				}
			}

			key.remote_port = 0;
			__builtin_memset(&key.remote.s6_addr32, 0, sizeof(struct in6_addr));
			// 收到的是握手回复的话，转发到用户态AF_XDP处理
			return XDP_PASS;
			// 路由器通过IPIP ICMP ping 加密隧道对端时，应该期待ICMP也从IPIP隧道返回。
			// 其他情况下，不走IPIP隧道直接回给局域网

			// 查询是否隧道下行包
			// 1. 封包解密

			// 2. 重置为内层隧道的类型，查找邻居，直接转发
			iph = iph + 1;
			h_proto = bpf_htons(ETH_P_IP);
#endif // CLIENT
		} else if (iph->protocol == IPPROTO_UDP) {
#ifdef SERVER
			// 可能最终是要进隧道的, 想办法转发给einat_ebpf找到目标的ip和udp，然后改写ip直接加密进隧道
#endif // SERVER
#ifdef CLIENT
			// 客户端不会有UDP，也不做nat
			return XDP_PASS;
#endif // CLIENT
		} else {
			// 不是上行，也不是下行流量，不管
			return XDP_PASS;
		}
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {

		ip6h = (void*)(eth + 1);
		if (ip6h + 1 > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		// todo 支持上行IPv6 封装
		// if (ip6h->nexthdr == IPPROTO_IPV6) {
		// }

		if (ip6h->nexthdr == IPPROTO_TCP) {
			return XDP_PASS;
		} else {
			return XDP_PASS;
		}
	} else {
		return XDP_PASS;
	}

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	// 到这里是下行隧道的转发了
	// 客户端，由于nat放到了隧道对端去做，这里的ipv4/ipv6 dst都已经是局域网了
	// 服务端，需要做nat
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
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS; // 如果邻居表ARP为空，需要PASS上去做ARP解析

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

	struct bpf_crypto_params crypto_params;
};

SEC("syscall")
int set_tunnel(struct tunnel_args *args)
{
	// 修改map
	int err = 0;

	struct bpf_crypto_ctx *cctx;
    cctx = bpf_crypto_ctx_create(&args->crypto_params, sizeof(struct bpf_crypto_params), &err);
	if (!cctx) {
		return err;
	}

	(void)cctx;

    return 0;
}

char _license[] SEC("license") = "GPL";

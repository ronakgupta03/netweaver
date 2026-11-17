// SPDX-License-Identifier: GPL-2.0
//
// NetWeaver eBPF classifier: marks egress packets by cgroup, enforces
// per-cgroup quarantine drops and token-bucket rate limits, and accounts
// ingress/egress bytes and packets per cgroup.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define NW_MIN_BURST_BYTES (64ULL * 1024ULL)
#define NW_NS_PER_SEC      1000000000ULL
#define NW_RATE_FAST_CAP   (1ULL << 34)

struct nw_target {
	__u32 mark;
	__u32 drop;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct nw_target);
} nw_targets SEC(".maps");

struct nw_counters {
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_pkts;
	__u64 tx_pkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct nw_counters);
} nw_stats SEC(".maps");

struct nw_rate {
	__u64 rate_bps;
	__u64 last_ns;
	__u64 tokens;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct nw_rate);
} nw_ratelimits SEC(".maps");

static __always_inline void record_tx(__u64 cgid, __u32 len)
{
	struct nw_counters *c = bpf_map_lookup_elem(&nw_stats, &cgid);
	if (c) {
		__sync_fetch_and_add(&c->tx_bytes, (__u64)len);
		__sync_fetch_and_add(&c->tx_pkts, 1);
		return;
	}
	struct nw_counters init = {
		.rx_bytes = 0,
		.tx_bytes = (__u64)len,
		.rx_pkts  = 0,
		.tx_pkts  = 1,
	};
	if (bpf_map_update_elem(&nw_stats, &cgid, &init, BPF_NOEXIST) != 0) {
		c = bpf_map_lookup_elem(&nw_stats, &cgid);
		if (c) {
			__sync_fetch_and_add(&c->tx_bytes, (__u64)len);
			__sync_fetch_and_add(&c->tx_pkts, 1);
		}
	}
}

static __always_inline void record_rx(__u64 cgid, __u32 len)
{
	struct nw_counters *c = bpf_map_lookup_elem(&nw_stats, &cgid);
	if (c) {
		__sync_fetch_and_add(&c->rx_bytes, (__u64)len);
		__sync_fetch_and_add(&c->rx_pkts, 1);
		return;
	}
	struct nw_counters init = {
		.rx_bytes = (__u64)len,
		.tx_bytes = 0,
		.rx_pkts  = 1,
		.tx_pkts  = 0,
	};
	if (bpf_map_update_elem(&nw_stats, &cgid, &init, BPF_NOEXIST) != 0) {
		c = bpf_map_lookup_elem(&nw_stats, &cgid);
		if (c) {
			__sync_fetch_and_add(&c->rx_bytes, (__u64)len);
			__sync_fetch_and_add(&c->rx_pkts, 1);
		}
	}
}

static __always_inline int check_ratelimit(__u64 cgid, __u32 len)
{
	struct nw_rate *r = bpf_map_lookup_elem(&nw_ratelimits, &cgid);
	if (!r)
		return 1;

	__u64 rate = r->rate_bps;
	if (rate == 0)
		return 1;

	__u64 burst = rate > NW_MIN_BURST_BYTES ? rate : NW_MIN_BURST_BYTES;
	__u64 now = bpf_ktime_get_ns();
	__u64 last = r->last_ns;
	__u64 tokens = r->tokens;

	if (last == 0) {
		last = now;
		if (tokens == 0 || tokens > burst)
			tokens = burst;
	} else if (now > last) {
		__u64 elapsed = now - last;
		__u64 add = 0;

		if (elapsed >= NW_NS_PER_SEC) {
			if (rate >= burst) {
				add = burst;
			} else {
				__u64 secs = elapsed / NW_NS_PER_SEC;
				if (secs >= NW_MIN_BURST_BYTES) {
					add = burst;
				} else {
					__u64 rem = elapsed % NW_NS_PER_SEC;
					add = secs * rate + (rem * rate) / NW_NS_PER_SEC;
				}
			}
		} else {
			if (rate > NW_RATE_FAST_CAP) {
				add = (elapsed / 1000ULL) * (rate / 1000000ULL);
			} else {
				add = (elapsed * rate) / NW_NS_PER_SEC;
			}
		}

		if (add > 0) {
			if (tokens >= burst || add >= burst - tokens) {
				tokens = burst;
				last = now;
			} else {
				tokens += add;
				if (rate <= NW_RATE_FAST_CAP && add <= NW_RATE_FAST_CAP) {
					last += (add * NW_NS_PER_SEC) / rate;
				} else {
					last = now;
				}
			}
		}
	}

	__u64 pkt_len = (__u64)len;
	if (tokens < pkt_len) {
		r->last_ns = last;
		r->tokens = tokens;
		return 0;
	}

	r->last_ns = last;
	r->tokens = tokens - pkt_len;
	return 1;
}

SEC("cgroup_skb/egress")
int nw_mark(struct __sk_buff *skb)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct nw_target *t = bpf_map_lookup_elem(&nw_targets, &cgid);

	if (t && t->drop)
		return 0;

	if (!check_ratelimit(cgid, skb->len))
		return 0;

	record_tx(cgid, skb->len);

	if (t)
		skb->mark = t->mark;
	return 1;
}

SEC("cgroup_skb/ingress")
int nw_ingress(struct __sk_buff *skb)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct nw_target *t = bpf_map_lookup_elem(&nw_targets, &cgid);

	if (t && t->drop)
		return 0;

	record_rx(cgid, skb->len);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";

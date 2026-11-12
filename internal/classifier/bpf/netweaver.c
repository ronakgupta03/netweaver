// SPDX-License-Identifier: GPL-2.0
//
// NetWeaver eBPF classifier: marks egress packets by cgroup, replacing the
// nftables `socket cgroupv2` marking rules, and drops traffic from the
// quarantine cgroup used by strict (kill-switch) policies.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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

SEC("cgroup_skb/egress")
int nw_mark(struct __sk_buff *skb)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct nw_target *t = bpf_map_lookup_elem(&nw_targets, &cgid);

	if (!t)
		return 1;
	if (t->drop)
		return 0;

	skb->mark = t->mark;
	return 1;
}

char LICENSE[] SEC("license") = "GPL";

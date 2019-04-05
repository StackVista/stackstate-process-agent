#ifndef __TCPTRACER_BPF_H
#define __TCPTRACER_BPF_H

#include <linux/types.h>

#define GUESS_SADDR      0
#define GUESS_DADDR      1
#define GUESS_FAMILY     2
#define GUESS_SPORT      3
#define GUESS_DPORT      4
#define GUESS_NETNS      5
#define GUESS_DADDR_IPV6 6

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define DIRECTION_UNKNOWN 0
#define DIRECTION_OUTGOING 1
#define DIRECTION_INCOMING 2

// We observed the connection being initialized
#define STATE_INITIALIZING 0
// We observed the connection being active
#define STATE_ACTIVE 1
// We observed the connection being active and then closed
#define STATE_ACTIVE_CLOSED 2
// We just observed the closing of the connection. We did not see any activity, so we treat this as a failed connection
// It is still reported to be able to close connections coming from /proc
#define STATE_CLOSED 3

struct proc_t {
    char comm[TASK_COMM_LEN];
};

struct conn_stats_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	// These are big to have a 64 bit aligned struct
    __u32 direction;
    // Was the connection active or closed?
    __u32 state;
};

struct conn_stats_ts_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	__u32 laddr;
	__u32 raddr;
	__u16 lport;
	__u16 rport;
	__u32 netns;
	__u32 pid;
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 laddr_h;
	__u64 laddr_l;
	__u64 raddr_h;
	__u64 raddr_l;
	__u16 lport;
	__u16 rport;
	__u32 netns;
	__u32 pid;
};

#define TCPTRACER_STATE_UNINITIALIZED 0
#define TCPTRACER_STATE_CHECKING      1
#define TCPTRACER_STATE_CHECKED       2
#define TCPTRACER_STATE_READY         3

struct tcptracer_status_t {
	__u64 state;

	/* checking */
	struct proc_t proc;
	__u64 what;
	__u64 offset_saddr;
	__u64 offset_daddr;
	__u64 offset_sport;
	__u64 offset_dport;
	__u64 offset_netns;
	__u64 offset_ino;
	__u64 offset_family;
	__u64 offset_daddr_ipv6;

	__u64 err;

	__u32 daddr_ipv6[4];
	__u32 netns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 padding;
};

#endif

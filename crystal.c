/* crystal.c
 * 
 * This kernel module is for quick UPD 5 tuples hash lookup
 *
 * Kai Luo (kailuo.nk@gmail.com)
 *
 * All rights reserved.
 *
 */

#include <linux/module.h>    /* Needed by all modules */
#include <linux/kernel.h>    /* Needed for KERN_INFO */
#include <linux/net.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <linux/kallsyms.h>
#include <uapi/linux/icmp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/inet_hashtables.h>

#define UDP_QUIC 200
#define SOCK_QUIC 61
#define SOCK_USE_QUIC 62

#if 0
#define DEBUG_QUIC(...) do { \
    printk(__VA_ARGS__);     \
} while(0)
#else
#define DEBUG_QUIC(...)
#endif

static int quic_rcv(struct sk_buff *skb);
static void quic_err(struct sk_buff *skb, u32 info);

static struct net_protocol quic_protocol = {
    /* TODO: we need implement early_demux later */
    .early_demux = NULL,
    .handler     = quic_rcv,
    .err_handler = quic_err,
    .no_policy   = 1,
    .netns_ok    = 1,
};

struct quic_hslot {
    struct hlist_head head;
    spinlock_t lock;
};

struct quic_table {
    struct quic_hslot *hash;
    unsigned int mask;
} quic_table;

static struct net_protocol **ip_protos;
static void *orig_protocol;
static int (*orig_udp_rcv)(struct sk_buff *skb);
static int (*orig_queue_rcv_skb)(struct sock *sk, struct sk_buff *skb);
static int (*orig_udp_setsockopt)(struct sock *sk, int level, int optname,
                                  char __user *optval, unsigned int optlen);
#ifdef CONFIG_COMPAT
static int (*orig_compat_setsockopt)(struct sock *sk, int level, int optname,
                                     char __user *optval, unsigned int optlen);
#endif // CONFIG_COMPAT
static void (*orig_ip_icmp_error)(struct sock *sk, struct sk_buff *skb, int err,
                                  __be16 port, u32 info, u8 *payload);

static inline bool use_quic(struct sock *sk)
{
    return sock_flag(sk, SOCK_USE_QUIC);
}

static inline int set_quic_opt(struct sock *sk, char __user *optval, unsigned int optlen)
{
    int val;

    if (optlen < sizeof(int))
        return -EINVAL;

    if (get_user(val, (int __user *)optval))
        return -EFAULT;

    lock_sock(sk);

    if (val) {
        sock_set_flag(sk, SOCK_USE_QUIC);
    } else {
        sock_reset_flag(sk, SOCK_USE_QUIC);
    }

    release_sock(sk);

    return 0;
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
                           char __user *optval, unsigned int optlen)
{
    if ((level == SOL_UDP) && (optname == UDP_QUIC)) {
        return set_quic_opt(sk, optval, optlen);
    }

    return orig_udp_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_quic_setsockopt(struct sock *sk, int level, int optname,
                                  char __user *optval, unsigned int optlen)
{
    if ((level == SOL_UDP) && (optname == UDP_QUIC)) {
        return set_quic_opt(sk, optval, optlen);
    }

    return orig_compat_setsockopt(sk, level, optname, optval, optlen);
}
#endif // CONFIG_COMPAT

static inline bool is_quic(struct sock *sk)
{
    smp_rmb();
    return sock_flag(sk, SOCK_QUIC);
}

static inline void set_quic(struct sock *sk)
{
    smp_wmb();
    sock_set_flag(sk, SOCK_QUIC);
}

static inline void unset_quic(struct sock *sk)
{
    smp_wmb();
    sock_reset_flag(sk, SOCK_QUIC);
}

static void udp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst)
{
    struct dst_entry *old;

    dst_hold(dst);
    old = xchg(&sk->sk_rx_dst, dst);
    dst_release(old);
}

static unsigned int quic_ehashfn(struct net *net, const __be32 laddr,
                 const __u16 lport, const __be32 faddr,
                 const __be16 fport)
{
    static u32 quic_ehash_secret __read_mostly;

    net_get_random_once(&quic_ehash_secret, sizeof(quic_ehash_secret));

    return __inet_ehashfn(laddr, lport, faddr, fport,
                          quic_ehash_secret + net_hash_mix(net));
}

static inline struct sock *__quic_lib_lookup(struct net *net, __be32 saddr,
                                             __be16 sport, __be32 daddr,
                                             __be16 dport, int dif)
{
    INET_ADDR_COOKIE(acookie, saddr, daddr)
    unsigned short hnum = ntohs(dport);
    const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
    struct sock *sk;
    unsigned int hash = quic_ehashfn(net, daddr, hnum, saddr, sport);
    unsigned int slot = hash & quic_table.mask;
    struct quic_hslot *hslot = &quic_table.hash[slot];

    DEBUG_QUIC("quic lookup: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
               daddr, saddr, hnum, ntohs(sport), hash, slot);

begin:
    udp_portaddr_for_each_entry_rcu(sk, &hslot->head) {
        if (sk->sk_hash != hash)
            continue;
        if (likely(INET_MATCH(sk, net, acookie, saddr, daddr, ports, dif))) {
            if (unlikely(!is_quic(sk))) {
                goto begin;
            }
            DEBUG_QUIC("quic lookup success: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
                       daddr, saddr, hnum, ntohs(sport), hash, slot);
            goto found;
        }
    }

    sk = NULL;
found:
    return sk;
}

static void quic_err(struct sk_buff *skb, u32 info)
{
    struct inet_sock *inet;
    const struct iphdr *iph = (const struct iphdr *)skb->data;
    struct udphdr *uh = (struct udphdr *)(skb->data+(iph->ihl<<2));
    const int type = icmp_hdr(skb)->type;
    const int code = icmp_hdr(skb)->code;
    struct sock *sk;
    int harderr;
    int err;
    struct net *net = dev_net(skb->dev);

    sk = __quic_lib_lookup(net, iph->daddr, uh->dest,
             iph->saddr, uh->source, skb->dev->ifindex);

    if (sk == NULL) {
        sk = __udp4_lib_lookup(net, iph->daddr, uh->dest,
                 iph->saddr, uh->source, skb->dev->ifindex, &udp_table);
    }

    if (sk == NULL) {
        ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
        return;    /* No socket for error */
    }

    err = 0;
    harderr = 0;
    inet = inet_sk(sk);

    switch (type) {
    default:
    case ICMP_TIME_EXCEEDED:
        err = EHOSTUNREACH;
        break;
    case ICMP_SOURCE_QUENCH:
        goto out;
    case ICMP_PARAMETERPROB:
        err = EPROTO;
        harderr = 1;
        break;
    case ICMP_DEST_UNREACH:
        if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
            ipv4_sk_update_pmtu(skb, sk, info);
            if (inet->pmtudisc != IP_PMTUDISC_DONT) {
                err = EMSGSIZE;
                harderr = 1;
                break;
            }
            goto out;
        }
        err = EHOSTUNREACH;
        if (code <= NR_ICMP_UNREACH) {
            harderr = icmp_err_convert[code].fatal;
            err = icmp_err_convert[code].errno;
        }
        break;
    case ICMP_REDIRECT:
        ipv4_sk_redirect(skb, sk);
        goto out;
    }

    /*
     *    RFC1122: OK.  Passes ICMP errors back to application, as per
     *    4.1.3.3.
     */
    if (!inet->recverr) {
        if (!harderr || sk->sk_state != TCP_ESTABLISHED)
            goto out;
    } else
        orig_ip_icmp_error(sk, skb, err, uh->dest, info, (u8 *)(uh+1));

    sk->sk_err = err;
    sk->sk_error_report(sk);
out:
    return;
}

static int quic_hash_connect(struct sock *sk, __be32 laddr,
                             __u16 hnum, __be32 faddr, __be16 fport)
{
    INET_ADDR_COOKIE(acookie, faddr, laddr)
    const __portpair ports = INET_COMBINED_PORTS(fport, hnum);
    struct net *net = sock_net(sk);
    unsigned int hash = quic_ehashfn(net, laddr, hnum, faddr, fport);
    unsigned int slot = hash & quic_table.mask;
    struct quic_hslot *hslot = &quic_table.hash[slot];
    struct sock *sk2;

    DEBUG_QUIC("quic connect: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
               laddr, faddr, hnum, ntohs(fport), hash, slot);

    udp_lib_unhash(sk);
    /* udp_lib_unhash will set inet_num to 0, so need set it back */
    inet_sk(sk)->inet_num = hnum;
    
    /* TODO: there may be performance issue, need to improve */ 
    // synchronize_rcu();

    spin_lock_bh(&hslot->lock);

    udp_portaddr_for_each_entry(sk2, &hslot->head) {
        if (sk2->sk_hash != hash)
            continue;
        if (likely(INET_MATCH(sk2, net, acookie, faddr, laddr, ports, sk->sk_bound_dev_if))) {
            spin_unlock_bh(&hslot->lock);
            return -1;
        }
    }

    sk->sk_hash = hash;
    sock_hold(sk);
    set_quic(sk);
    hlist_add_head_rcu(&udp_sk(sk)->udp_portaddr_node, &hslot->head);
    sock_prot_inuse_add(net, sk->sk_prot, 1);

    spin_unlock_bh(&hslot->lock);

    DEBUG_QUIC("quic connect success: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
               laddr, faddr, hnum, ntohs(fport), hash, slot);

    return 0;
}

void quic_unhash(struct sock *sk)
{
    unsigned int slot;
    struct quic_hslot *hslot;

    lock_sock(sk);

    if (!is_quic(sk)) {
        release_sock(sk);
        return udp_lib_unhash(sk);
    }

    BUG_ON(hlist_unhashed(&udp_sk(sk)->udp_portaddr_node));

    slot = sk->sk_hash & quic_table.mask;
    hslot = &quic_table.hash[slot];

    DEBUG_QUIC("quic unhash: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
               inet_sk(sk)->inet_rcv_saddr, inet_sk(sk)->inet_daddr, inet_sk(sk)->inet_num,
               ntohs(inet_sk(sk)->inet_dport), sk->sk_hash, slot);

    spin_lock_bh(&hslot->lock);

    hlist_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
    unset_quic(sk);
    WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
    __sock_put(sk);
    sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

    spin_unlock_bh(&hslot->lock);

    release_sock(sk);

    DEBUG_QUIC("quic unhash success: laddr = %x, faddr = %x, hnum = %u, fport = %u, hash = %x, slot = %u\n",
               inet_sk(sk)->inet_rcv_saddr, inet_sk(sk)->inet_daddr, inet_sk(sk)->inet_num,
               ntohs(inet_sk(sk)->inet_dport), sk->sk_hash, slot);

    /* TODO: there may be performance issue, need to improve */
    // synchronize_rcu();
}

int quic_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct inet_sock *inet = inet_sk(sk);
    struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
    struct flowi4 *fl4;
    struct rtable *rt;
    __be32 saddr;
    int oif;
    int err;

    if (addr_len < sizeof(*usin))
        return -EINVAL;

    if (usin->sin_family != AF_INET)
        return -EAFNOSUPPORT;

    lock_sock(sk);

    if (is_quic(sk)) {
        err = -EISCONN;
        goto out; 
    }

    if (!use_quic(sk)) {
        release_sock(sk);
        return ip4_datagram_connect(sk, uaddr, addr_len);
    }

    if (sk->sk_state != TCP_CLOSE) {
        err = -EINVAL;
        goto out;
    }

    sk_dst_reset(sk);

    if (ipv4_is_multicast(usin->sin_addr.s_addr) ||
        ipv4_is_lbcast(usin->sin_addr.s_addr) ||
        ipv4_is_zeronet(usin->sin_addr.s_addr)) {
        err = -ENETUNREACH;
        goto out;
    }

    oif = sk->sk_bound_dev_if;
    saddr = inet->inet_saddr;
    fl4 = &inet->cork.fl.u.ip4;
    rt = ip_route_connect(fl4, usin->sin_addr.s_addr, saddr,
                  RT_CONN_FLAGS(sk), oif,
                  sk->sk_protocol,
                  inet->inet_sport, usin->sin_port, sk);
    if (IS_ERR(rt)) {
        err = PTR_ERR(rt);
        if (err == -ENETUNREACH)
            IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
        goto out;
    }

    if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
        err = -ENETUNREACH;
        goto out;
    }

    saddr = inet->inet_rcv_saddr;
    if (!saddr) {
        saddr = fl4->saddr;
    }
    if (!saddr) {
        err = -ENONET;
        goto out;
    }

    if (quic_hash_connect(sk, saddr, inet->inet_num,
                          fl4->daddr, usin->sin_port)) {
        err = -EADDRINUSE;
        goto out;
    }

    if (!inet->inet_saddr)
        inet->inet_saddr = fl4->saddr;    /* Update source address */
    if (!inet->inet_rcv_saddr) {
        inet->inet_rcv_saddr = fl4->saddr;
    }

    inet->inet_daddr = fl4->daddr;
    inet->inet_dport = usin->sin_port;
    sk->sk_state = TCP_ESTABLISHED;
    sk_set_txhash(sk);
    inet->inet_id = jiffies;

    sk_dst_set(sk, &rt->dst);
    err = 0;
out:
    release_sock(sk);
    return err;
}

static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
                                                 __be16 sport, __be16 dport,
                                                 struct udp_table *udptable)
{
    struct sock *sk;
    struct net *net;
    const struct iphdr *iph = ip_hdr(skb);

    net = dev_net(skb->dev);

    sk = __quic_lib_lookup(net, iph->saddr, sport, iph->daddr, dport, inet_iif(skb));

    if (sk != NULL)
        return sk;

    return __udp4_lib_lookup(net, iph->saddr, sport,
                             iph->daddr, dport, inet_iif(skb),
                             udptable);
}

static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
                                 int proto)
{
    UDP_SKB_CB(skb)->partial_cov = 0;
    UDP_SKB_CB(skb)->cscov = skb->len;

    return skb_checksum_init_zero_check(skb, proto, uh->check,
                                        inet_compute_pseudo);
}

static int quic_rcv(struct sk_buff *skb)
{
    int proto = IPPROTO_UDP;
    struct udp_table *udptable = &udp_table;
    struct sock *sk;
    struct udphdr *uh;
    unsigned short ulen;
    struct rtable *rt = skb_rtable(skb);
    __be32 saddr, daddr;
    struct net *net = dev_net(skb->dev);

    if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
        return orig_udp_rcv(skb);

    /*
     *  Validate the packet.
     */
    if (!pskb_may_pull(skb, sizeof(struct udphdr)))
        goto drop;        /* No space for header. */

    uh   = udp_hdr(skb);
    ulen = ntohs(uh->len);
    saddr = ip_hdr(skb)->saddr;
    daddr = ip_hdr(skb)->daddr;

    if (ulen > skb->len)
        goto short_packet;

    if (proto == IPPROTO_UDP) {
        /* UDP validates ulen. */
        if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
            goto short_packet;
        uh = udp_hdr(skb);
    }

    if (udp4_csum_init(skb, uh, proto))
        goto csum_error;

    sk = skb_steal_sock(skb);
    if (sk) {
        struct dst_entry *dst = skb_dst(skb);
        int ret;

        if (unlikely(sk->sk_rx_dst != dst))
            udp_sk_rx_dst_set(sk, dst);

        ret = orig_queue_rcv_skb(sk, skb);
        sock_put(sk);
        /* a return value > 0 means to resubmit the input, but
         * it wants the return to be -protocol, or 0
         */
        if (ret > 0)
            return -ret;
        return 0;
    }

    sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);

    if (sk != NULL) {
        int ret;

        if (inet_get_convert_csum(sk) && uh->check && !IS_UDPLITE(sk))
            skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
                         inet_compute_pseudo);

        ret = orig_queue_rcv_skb(sk, skb);

        /* a return value > 0 means to resubmit the input, but
         * it wants the return to be -protocol, or 0
         */
        if (ret > 0)
            return -ret;
        return 0;
    }

    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
        goto drop;
    nf_reset(skb);

    /* No socket. Drop packet silently, if checksum is wrong */
    if (udp_lib_checksum_complete(skb))
        goto csum_error;

    UDP_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
    icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

    /*
     * Hmm.  We got an UDP packet to a port to which we
     * don't wanna listen.  Ignore it.
     */
    kfree_skb(skb);
    return 0;

short_packet:
    LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
                   proto == IPPROTO_UDPLITE ? "Lite" : "",
                   &saddr, ntohs(uh->source),
                   ulen, skb->len,
                   &daddr, ntohs(uh->dest));
    goto drop;

csum_error:
    /*
     * RFC1122: OK.  Discards the bad packet silently (as far as
     * the network is concerned, anyway) as per 4.1.3.4 (MUST).
     */
    LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
                   proto == IPPROTO_UDPLITE ? "Lite" : "",
                   &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
                   ulen);
    UDP_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop:
    UDP_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
    kfree_skb(skb);
    return 0;
}

int __init quic_table_init(void)
{
    const unsigned int entries = 512 * 1024; /* must be 2^n */
    unsigned int i;

    quic_table.hash = (struct quic_hslot *) vmalloc(entries * sizeof(struct quic_hslot));

    if (quic_table.hash == NULL) {
        printk(KERN_INFO "can not vmalloc memory for quic_table hash\n");
        return -1;
    }

    quic_table.mask = entries - 1;

    for (i = 0; i <= quic_table.mask; i++) {
        INIT_HLIST_HEAD(&quic_table.hash[i].head);
        spin_lock_init(&quic_table.hash[i].lock);
    }

    return 0;
}

int __init init_module(void)
{
    int err = 0;
    unsigned long sym_addr;

    printk(KERN_INFO "crystal init\n");

    sym_addr = kallsyms_lookup_name("udp_rcv");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find udp_rcv\n");
        return -1;
    }

    orig_udp_rcv = sym_addr;

    sym_addr = kallsyms_lookup_name("udp_queue_rcv_skb");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find udp_queue_rcv_skb\n");
        return -1;
    }

    orig_queue_rcv_skb = sym_addr;

    sym_addr = kallsyms_lookup_name("udp_err");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find udp_err\n");
        return -1;
    }

    quic_protocol.err_handler = sym_addr;

    sym_addr = kallsyms_lookup_name("udp_setsockopt");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find udp_setsockopt\n");
        return -1;
    }

    orig_udp_setsockopt = sym_addr;

#ifdef CONFIG_COMPAT
    sym_addr = kallsyms_lookup_name("compat_udp_setsockopt");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find compat_udp_setsockopt\n");
        return -1;
    }

    orig_compat_setsockopt = sym_addr;
#endif // CONFIG_COMPAT

    sym_addr = kallsyms_lookup_name("ip_icmp_error");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find ip_icmp_error\n");
        return -1;
    }

    orig_ip_icmp_error = sym_addr;

    sym_addr = kallsyms_lookup_name("inet_protos");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find inet_protos\n");
        return -1;
    }

    ip_protos = sym_addr;

    err = quic_table_init();
    if (err < 0) {
        return -1;
    }

    orig_protocol = ip_protos[IPPROTO_UDP];

    ip_protos[IPPROTO_UDP] = &quic_protocol;

    udp_prot.unhash = quic_unhash;
    udp_prot.connect = quic_connect;
    udp_prot.setsockopt = quic_setsockopt;
#ifdef CONFIG_COMPAT
    udp_prot.compat_setsockopt = compat_quic_setsockopt;
#endif // CONFIG_COMPAT

    return err;
}

void cleanup_module(void)
{
    printk(KERN_INFO "crystal cleanup\n");

#ifdef CONFIG_COMPAT
    udp_prot.compat_setsockopt = orig_compat_setsockopt;
#endif // CONFIG_COMPAT
    udp_prot.setsockopt = orig_udp_setsockopt;
    udp_prot.connect = ip4_datagram_connect;
    udp_prot.unhash = udp_lib_unhash;

    ip_protos[IPPROTO_UDP] = orig_protocol;

    /* TODO: safely free the memory */
    vfree(quic_table.hash);
}

MODULE_LICENSE("GPL");

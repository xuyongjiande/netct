/*
 * Module is used to drop packets for AppEx's Test. 
 */
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
 

/* Global variable for ntuple */
static uint __drop_index;
static uint __drop_type;
static uint __drop_num;
static uint __src_ip, __dst_ip, __dst_ip2;
static ushort __dst_port;
static ushort __dir;//direction
//static u8 __protocol;

/* Module info, GPL/VERSION and param */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("xirui.hw@gmail.com");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("used to drop packets which is pointed out by input info");

module_param(__drop_index, uint, 0);
module_param(__drop_type, uint, 0);
module_param(__drop_num, uint, 0);
module_param(__src_ip, uint, 0);
module_param(__dst_ip, uint, 0);
module_param(__dst_ip2, uint, 0);
module_param(__dst_port, ushort, 0);
module_param(__dir, ushort, 0);

//static unsigned int total_packets_num;

#define RETURN(value) {return value;}
#define RETURN_FOR(value) { \
	if (value == NF_DROP) \
		printk("[%s]-[%d]-DROP\n", __FUNCTION__, __LINE__); \
	else if (value == NF_ACCEPT) \
		printk("[%s]-[%d]-ACCEPT\n", __FUNCTION__, __LINE__); \
	return value;\
}

#define __HOOK_IN 		0x00
#define __HOOK_OUT		0x01

// To be improved...., Just for test Temporary
// It is so ugly..., 1,2,6,7,3,4,5,10,8,9
#define __MAKE_OUT_ORDER	0x10		
static int __out_order_index[10] = {0,1,4,5,6,2,3,8,9,7};
static struct sk_buff *__skb_ac[10];

//#define __DROP_CONFIRM_DATA	0x10
//#define __DROP_MULTI_DATA	0x20
#define __DROP_SYN_MASK 	0x07
#if 0
#define __DROP_SYN_END	0x0F
typedef enum {
	__DROP_FIRST_DATA = __DROP_SYN_END + 1,
	__DROP_FIRST_TWO_DATA,
	__DROP_LAST_ONE_DATA,
	__DROP_ALL_DATA,
	__DROP_LAST_ONE_DATA_AND_FIRST_RETRANS,
	__DROP_LAST_ONE_DATA_AND_FIRST_TWO_RETRANS
} __drop_enum;
#endif

// Test case 1: syn-ack or ack loss in handshake phase
static int __handshake_retransmit(struct tcphdr *th)
{
#define __DROP_SYN 	0x01
#define __DROP_SYN_ACK	0x02
#define __DROP_ACK	0x04
	
	/* bits 00-07: FOR SYN DROP COUNTS */
	/* bits 08-15: FOR SYN_ACK DROP COUNTS */
	/* bits 16-24: FOR ACK DROP COUNT*/
	//static int drop_flags; 
	static int drop_syn, drop_syn_ack, drop_ack;
	/* give some help to drop the ack packet */
	static u32 syn_seq, syn_ack_seq;

	if (th->syn && !th->ack) {
		/* the seq should not be changed */
		syn_seq = ntohl(th->seq); 
		if ((__drop_type & __DROP_SYN) && drop_syn++ < __drop_num) 
			RETURN(NF_DROP);
	} 

	if (th->syn && th->ack) {
		/* the seq should not be changed */
		syn_ack_seq = ntohl(th->seq);
		if ((__drop_type & __DROP_SYN_ACK) && drop_syn_ack++ < __drop_num)
			RETURN(NF_DROP);
	}

	if ((__drop_type & __DROP_ACK) && !th->syn && th->ack) {
		if (ntohl(th->ack_seq) != (syn_ack_seq + 1) || ntohl(th->seq) != (syn_seq + 1))
			RETURN(NF_ACCEPT);

		if (drop_ack++ < __drop_num)
			RETURN(NF_DROP);
	}
	RETURN(NF_ACCEPT);
}

static int __drop_confirm_data(struct tcphdr *th)
{
	static int data_index, data_drop_num;
	static u32 seq, ack_seq;

	RETURN(NF_DROP);
	if (!seq && !ack_seq && ++data_index == __drop_index) {
		seq = th->seq;
		ack_seq = th->ack_seq;
		RETURN(NF_DROP);
	} else if (seq == th->seq && ack_seq == th->ack_seq \
			&& ++data_drop_num < __drop_num) 
		RETURN(NF_DROP);

	RETURN(NF_ACCEPT);
}

/* supports up to 8 discard */
static int __drop_multi_data(struct tcphdr *th)
{
	typedef struct {
		u32 seq;
		u32 ack_seq;
	} drop_record_t;

	static int data_index; 
	static drop_record_t record[8];
	int i;
	
	for (i = 0; i < 8; i++) {
		if (record[i].seq == th->seq && record[i].ack_seq == th->ack_seq)
			RETURN(NF_ACCEPT);
	}

	data_index = data_index + 1;
	for (i = 0; i < 8; i++) {
		if (data_index == ((__drop_num >> (i * 4)) & 0xF)) {
			record[i].seq = th->seq;
			record[i].ack_seq = th->ack_seq;
			RETURN(NF_DROP);
		}
	}
	RETURN(NF_ACCEPT);
}

static struct timer_list local_in_timer;
static void __local_in_time_out(unsigned long data)
{
	int index = 0;
	struct sk_buff *skb;

	int (*okfn)(struct sk_buff *) = (void *)data;

	while (index < ARRAY_SIZE(__skb_ac) && (skb = __skb_ac[index++]) != NULL)
		okfn(skb);
	printk("%s-%d-index: %d\n", __FUNCTION__, __LINE__, index);
}

static int __make_out_order(struct sk_buff *skb, int (*okfn)(struct sk_buff *))
{
	static int rcv_index;
		
	if (rcv_index < ARRAY_SIZE(__skb_ac)) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);

		if (!rcv_index) {
			init_timer(&local_in_timer);			

			local_in_timer.data = (unsigned long)okfn;
			local_in_timer.expires = jiffies + 1;
			local_in_timer.function = __local_in_time_out;
			add_timer(&local_in_timer);
		}
		__skb_ac[__out_order_index[rcv_index++]] = new_skb;	
		RETURN(NF_DROP);
	} 

	RETURN(NF_ACCEPT);
}

static int __establish_retransmit(struct tcphdr *th)
{
	//if (__drop_type == __DROP_CONFIRM_DATA)
	if (__drop_index)
		return __drop_confirm_data(th);

	if (!__drop_index && __drop_num)
		return __drop_multi_data(th);

	RETURN(NF_ACCEPT);	
}

static unsigned int hook_local_in_func(const struct nf_hook_ops *ops, 
//static unsigned int hook_local_in_func(unsigned int hook, 
		struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *))
{
	if (unlikely(skb->protocol != htons(ETH_P_IP))) 
		RETURN(NF_ACCEPT);

	/* If you want to build a complex test scenarios, 
	 * there should be a filtering rules list to match the packets 
	 * which will be dropped. ToDo...
	 */
	if (pskb_may_pull(skb, sizeof(struct iphdr))) {
		struct iphdr *iph = (struct iphdr *)skb->data;
		
		if (iph->protocol != IPPROTO_TCP)
			RETURN(NF_ACCEPT);

		if (__drop_type & __DROP_SYN_MASK) {
			if ((iph->saddr != __src_ip || (__dst_ip && iph->daddr != __dst_ip && iph->daddr != __dst_ip2)) && 
					((__dst_ip && iph->saddr != __dst_ip && iph->saddr != __dst_ip2) || iph->daddr != __src_ip))
				RETURN(NF_ACCEPT);
		} else {

			if (!__dir && (iph->saddr != __src_ip || (__dst_ip && iph->daddr != __dst_ip && iph->daddr != __dst_ip2)))
				RETURN(NF_ACCEPT);
			if (__dir && ((__dst_ip && iph->saddr != __dst_ip && iph->saddr != __dst_ip2) || iph->daddr != __src_ip))
				RETURN(NF_ACCEPT);
		}

		if (pskb_may_pull(skb, (iph->ihl << 2) + sizeof(struct tcphdr))) {
			unsigned int data_len;
			struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));

			if (ntohs(th->dest) != __dst_port && ntohs(th->source) != __dst_port)
				RETURN(NF_ACCEPT);

			data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (th->doff << 2);
			if (__drop_type & __DROP_SYN_MASK)
				return __handshake_retransmit(th);
			else if (__drop_type == __MAKE_OUT_ORDER && data_len)
				return __make_out_order(skb, okfn);
			else if (data_len)
				return __establish_retransmit(th);
		}
	}
	RETURN(NF_ACCEPT);
}

// Temp Data... For Test
#define MAX_CONN_NUM 10
typedef struct {
	ushort sport;
	ushort dport;
	uint   seq;
	uint   ack_seq;
	uint   data_index;
	uint   drop_num;
} drop_conn_st;

static drop_conn_st conn_info[MAX_CONN_NUM];

static int __drop_handshake_pkts(struct tcphdr *th)
{
#define __DROP_SYN 	0x01
#define __DROP_SYN_ACK	0x02
	
	int i;

	for (i = 0; i < MAX_CONN_NUM; i++) {
		if (conn_info[i].sport == th->source && conn_info[i].dport == th->dest)
			break;
		if (conn_info[i].sport == 0)
			break;
	}

	if (th->syn && !th->ack) {
		if (i < MAX_CONN_NUM && conn_info[i].sport == 0) {
			conn_info[i].sport = th->source;
			conn_info[i].dport = th->dest;
			conn_info[i].drop_num = 0;
		}
		//if (__drop_type & __DROP_SYN)  
		if (conn_info[i].drop_num < 4) {
			conn_info[i].drop_num++;
			RETURN_FOR(NF_DROP);
		}	
	} 

	if (th->syn && th->ack) {
		if (__drop_type & __DROP_SYN_ACK)
			RETURN_FOR(NF_DROP);
	}

	RETURN_FOR(NF_ACCEPT);
}

static int __drop_confirm_pkts(struct sk_buff *skb)
{
	int i;
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));

	for (i = 0; i < MAX_CONN_NUM; i++) {	
		if (!__dir) {
			if (conn_info[i].sport == th->source && conn_info[i].dport == th->dest)
				break;
		} else if (conn_info[i].dport == th->source && conn_info[i].sport == th->dest) {
			break;
		}
	} 

	if (i < MAX_CONN_NUM) {
		if (++conn_info[i].data_index == __drop_index) {
			conn_info[i].seq = th->seq;
			conn_info[i].ack_seq = th->ack_seq;
			RETURN_FOR(NF_DROP);
		} else if (conn_info[i].seq == th->seq && conn_info[i].ack_seq == th->ack_seq) {
			if (conn_info[i].drop_num < 7) {
				conn_info[i].drop_num++;
				RETURN_FOR(NF_DROP);
			}
		} /*else if (conn_info[i].drop_num < 10) {
			conn_info[i].drop_num++;
			RETURN_FOR(NF_DROP);
		} */
	}

	RETURN_FOR(NF_ACCEPT);
}

static unsigned int hook_forward_func(const struct nf_hook_ops *ops, 
//static unsigned int hook_forward_func(unsigned int hook, 
		struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *))
{
	if (unlikely(skb->protocol != htons(ETH_P_IP))) 
		return NF_ACCEPT;

	if (pskb_may_pull(skb, sizeof(struct iphdr))) {
		struct iphdr *iph = (struct iphdr *)skb->data;
		
		if (iph->protocol != IPPROTO_TCP)
			return NF_ACCEPT;

		if (iph->saddr != __dst_ip || iph->daddr != __dst_ip)
			RETURN_FOR(NF_ACCEPT);

		if (iph->saddr != __src_ip && iph->daddr != __src_ip)
			RETURN_FOR(NF_ACCEPT);

		if (pskb_may_pull(skb, (iph->ihl << 2) + sizeof(struct tcphdr))) {
			struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));

			if (ntohs(th->dest) != __dst_port && ntohs(th->source) != __dst_port)
				RETURN_FOR(NF_ACCEPT);

			if (__drop_handshake_pkts(th) != NF_ACCEPT)
				RETURN_FOR(NF_DROP);

			if (ntohs(iph->tot_len) - (iph->ihl << 2) - (th->doff << 2))
				return __drop_confirm_pkts(skb);
		}
	}
	RETURN_FOR(NF_ACCEPT);
}

static unsigned int hook_local_out_func(const struct nf_hook_ops *ops, 
//static unsigned int hook_local_out_func(unsigned int hook, 
		struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *th;

	if (!(__drop_type & __DROP_SYN_MASK)) 
		RETURN(NF_ACCEPT);

	if (!skb->transport_header || !skb->network_header)
		RETURN(NF_ACCEPT);

	iph = (struct iphdr *)(skb->head + skb->network_header);
	if (iph->ihl != 5 || iph->version != 4)
		RETURN(NF_ACCEPT);

	if (iph->protocol != IPPROTO_TCP)
		RETURN(NF_ACCEPT);

	if ((iph->saddr != __src_ip || (iph->daddr != __dst_ip  && iph->daddr != __dst_ip2)) && 
			((iph->saddr != __dst_ip && iph->saddr != __dst_ip2) || iph->daddr != __src_ip))
		RETURN(NF_ACCEPT);

	th = (struct tcphdr *)(skb->head + skb->transport_header);	
	if (ntohs(th->dest) != __dst_port && ntohs(th->source) != __dst_port)
		RETURN(NF_ACCEPT);
	
	if (ntohs(iph->tot_len) - (iph->ihl << 2) - (th->doff << 2))
		RETURN(NF_ACCEPT);

	return __handshake_retransmit(th);;
}

/* Register to Kernel, support Local_in and Local_out now! */
static struct nf_hook_ops hook_ops[] __read_mostly = {
	{
		.hook           = hook_local_in_func,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_LOCAL_IN,
		.priority       = NF_IP_PRI_FIRST,
	},
	{
		.hook           = hook_forward_func,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_FORWARD,
		.priority       = NF_IP_PRI_FIRST,
	},
	{
		.hook           = hook_local_out_func,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_LOCAL_OUT,
		.priority       = NF_IP_PRI_FIRST,
	}
};

static void __usage(void) {
	printk("Drop packets modules For FastTCP (follow the below step): \n");
	printk("\t arg[1](necessary): __src_ip, such as \"__src_ip=xxxx(u32, host)\"\n");
	printk("\t arg[2](necessary): __dst_ip, such as \"__dst_ip=xxxx(u32, host)\"\n");
	printk("\t arg[3](optional) : __dst_ip, such as \"__dst_ip2=xxxx(u32, host)\"\n");
	printk("\t arg[4](necessary): __dst_port, such as \"__dst_port=xx(u16, host)\"\n");
	printk("\t arg[5](necessary): __drop_type\n");
	printk("\t arg[6](necessary): __drop_index\n");
	printk("\t arg[7](necessary): __drop_num\n");
	//printk("\t arg[5](optional) : __dir, support 0 (normal direction) and 1(converse direction), \n");
}

static int __init __hook_init(void)
{
	if (!__src_ip || /*!__dst_ip ||*/ !__dst_port) {
		__usage();
		return -1;
	}
	printk("Hook Info: __src_ip: %u, __dst_ip: %u, __dst_ip2: %u, __dst_port: %u, __drop_index: %u, __drop_num: %u, __drop_type: %u\n",
			__src_ip, __dst_ip, __dst_ip2, __dst_port, __drop_index, __drop_num, __drop_type);
	return nf_register_hooks(hook_ops, ARRAY_SIZE(hook_ops));
}

static void __exit __hook_exit(void)
{
	nf_unregister_hooks(hook_ops, ARRAY_SIZE(hook_ops));
}

module_init(__hook_init);
module_exit(__hook_exit);


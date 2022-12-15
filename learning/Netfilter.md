## Netfilter system



![img](https://arthurchiao.art/assets/img/deep-dive-into-iptables-netfilter/Netfilter-packet-flow.svg)

### Netfilter

![img](https://arthurchiao.art/assets/img/conntrack/netfilter-design.png)

- Netfilter 為整套 kernel space 做流量處理 (manipulation and filtering) 的系統
  - 紀錄
  - 放行
  - 修改
  - 丟棄
- `iptables` 為 user space 的工具，基於 packet filtering framework 實作 firewall
- netfilter 提供了 5 個 hook 點，packet 經過 protocol stack 時會觸發 kernel module 所註冊的 function



而 **netfilter** 只是 Linux kernel 中一種 **connection tracking** (CT) 的實作系統而已，舉例來講開源軟體 Cilium Infra 就實作了一個 connection tracking 的系統，主要利用了 eBPF 的機制：

![img](https://arthurchiao.art/assets/img/conntrack/cilium-conntrack.png)

- netfilter 除了包含 CT，同時也包含了 NAT 以及 netfilter hooks



以下幾個 hook 是 protocol stack 已經定義好的：

- `NF_IP_PRE_ROUTING` - packet 進入 protocol stack 後第一個所執行到的 hook。結束後 packet 會進行 routing 判斷
- `NF_IP_LOCAL_IN` - 如果目的為 local，則會執行此 hook
- `NF_IP_FORWARD` - 如果目的為其他機器，則會執行此 hook
- `NF_IP_LOCAL_OUT` - 如果從 local 準備出去的封包，在進入 protocol stack 後會執行此 hook
- `NF_IP_POST_ROUTING` - 不論 local 產或是 routing，只要是準備發送的包，都會執行此 hook

```c
// include/uapi/linux/netfilter_ipv4.h

#define NF_IP_PRE_ROUTING    0 /* After promisc drops, checksum checks. */
#define NF_IP_LOCAL_IN       1 /* If the packet is destined for this box. */
#define NF_IP_FORWARD        2 /* If the packet is destined for another interface. */
#define NF_IP_LOCAL_OUT      3 /* Packets coming from a local process. */
#define NF_IP_POST_ROUTING   4 /* Packets about to hit the wire. */
#define NF_IP_NUMHOOKS       5

enum nf_inet_hooks {
    NF_INET_PRE_ROUTING,
    NF_INET_LOCAL_IN,
    NF_INET_FORWARD,
    NF_INET_LOCAL_OUT,
    NF_INET_POST_ROUTING,
    NF_INET_NUMHOOKS
};
```



Hook 被執行後，會回傳執行結果給 netfilter，代表 pakcet 最後會執行什麼操作：

```c
// include/uapi/linux/netfilter.h

#define NF_DROP   0  // drop
#define NF_ACCEPT 1  // accept
#define NF_STOLEN 2  // 暫時 hold 住
#define NF_QUEUE  3  // 放到 nfqueue
#define NF_REPEAT 4  // 再執行一次 handle
```



### Table

`iptable` 使用 table 來建立 rule，並根據 "the type of decisions they are used to make" 的標準處理，總共有下列這些 table：

- `nat` (network address translation) - 用於處理網路轉換，決定是否/如何修改 src/dst
- `filter` - 用於判斷 packet 是否能通過 (filtering)
- ` mangle` - 用於修改 IP header，像是 TTL
- `raw` - 讓 packet 繞過 connection tracking 的框架
  - 建立在 netfilter 上的 connection tracking 機制使得 `iptables` 把 packets 視為一系列的對話
- `security` - mark packet 為 SELinux



### Chain

而 table 中會新增不同的 rule，這些 rules 會組成 chain，而下列為 chain name 跟 netfilter hook 的對應：

- `PREROUTING` - 由 `NF_IP_PRE_ROUTING` hook 觸發
- `INPUT` - 由 `NF_IP_LOCAL_IN` hook 觸發
- `FORWARD` - 由 `NF_IP_FORWARD` hook 觸發
- `OUTPUT` - 由 `NF_IP_LOCAL_OUT` hook 觸發
- `POSTROUTING` - 由 `NF_IP_POST_ROUTING` hook 觸發



以下為 built-in table 跟 chain 的組合：

![image-20221211113013655](/Users/u1f383/Library/Application Support/typora-user-images/image-20221211113013655.png)

- NAT 又分成 `DNAT` (destintion) 或是 `SNAT` (source)
- 觸發 hook 時，table 執行的流程為由上到下
- 特定事件發生時會讓 table 的 chain 被跳過
  - 只有第一個 packet 會執行到 NAT rule，並且此 packet 的動作會影響到後續的封包
- chain 的 priority 為從左到右，而下列根據不同的情境會使用到不同的 table：
  - 收到的、目的是 local 的 packet - `PRETOUTING` -> `INPUT`
  - 收到的、目的是其他機器的 packet - `PRETOUTING` -> `FORWARD` -> `POSTROUTING`
  - local 產生的 packet - `OUTPUT` -> `POSTROUTING`

舉個例子做個總結，**一個收到的、目的是 local 的包** - 經過 `PRETOUTING` chain 上面的 `raw`、`mangle`、`nat` table，再來是 `INPUT` chain 的 `mangle`、`filter`、`security`、`nat` table，最後才會到 socket。



### Rule of Iptable

`iptable` 會在指定 table + chain 中加上一個規則，當 pakcet 到達指定 table + chain 時，如果滿足特定的條件，會執行到規則對應到的動作，這些符合某個條件而觸發的動作 (action) 稱作目標 (target)，分成兩種：

- Terminating targets - target 會終止 chain matching，將判斷轉交給 netfilter hook，由他決定 packet 是否要繼續傳下去
- Non-terminating targets - 單純執行一個操作
  - 操作 `jump target` 為特例，其功能在於跳轉到其他 chain 做處理

因為使用者自定義的 chain 沒辦法註冊到 netfilter hook，因此需要透過 `jump target` 的方式來跳轉，可以將這種形態的 chain 視為原本 chain 的擴展。而自定義的 chain 執行結束後，可以回到原本的 netfilter hook，也可以繼續執行下一個自定義 chain。



### Connection Tracking (CT)

功能為發現並追蹤這些 connection 的狀態，具體包括：

- 從 packet 中提取 tuple 資訊，辨別 **data flow** 和對應的 **connection**
- 紀錄各個連接的創建時間、發送包數、發送 byte 數等等
- 回收過期的連接 (GC)
- 為更上層的功能 (例如 NAT) 提供服務

如果要做到上述的那些事情，需要做下面幾點事情：

- 攔截 packet
- 為所有連接維護一個 conntrack table
- 根據 packet 不斷更新 table



每組封包流都會對應到下面的其中一個狀態：

- `NEW` - 與現有的封包都不相關，但是封包是合法的，就為此封包建立一個新的 connection
  - connection-aware - TCP
  - connectionless - UDP
- `ESTABLISHED` - 當 connection 收到合法的 response，狀態就會從 `NEW` 變成 `ESTABLISHED`
  - TCP - `SYN/ACK`
  - UDP 和 ICMP - dst/src 為 request 的 src/dst 的封包
- `RELATED` - 不屬於現有 connection 但有一定關係，像是 helper connection
  - FTP or 其他 protocol - 嘗試建立連線時發送的 ICMP
- `INVALID` - 不屬於現有 connection，並因為無法識別、routing 而不能建立新的 connection
- `UNTRACKED` - 如果在 `raw` table 中標記成 `UNTRACKED`，此 packet 就不會進到 connection tracking
- `SNAT` - packet 的 source 被 NAT 修改之後會進入的狀態
  - connection tracking system 會在收到 response 時自動做轉換
- `DNAT` - packet 的 destination 被 NAT 修改之後會進入的狀態
  - connection tracking system 會在收到 response 時自動做轉換



### CT Source tracing

網路各個層級的參考說明：

![](https://www.researchgate.net/publication/327483011/figure/fig2/AS:668030367436802@1536282259885/The-logical-mapping-between-OSI-basic-reference-model-and-the-TCP-IP-stack.jpg)

#### 1. Netfilter conntrack

定義一個 tuple (include/net/netfilter/nf_conntrack_tuple.h)：

```c
// 這個部分跟 nf_conntrack_tuple.u 成員有點相似，也是用來定義協議
union nf_conntrack_man_proto {
    __be16 all;

    struct {
        __be16 port;
    } tcp;
    struct {
        __be16 port;
    } udp;
    struct {
        __be16 id;
    } icmp;
    struct {
        __be16 port;
    } dccp;
    struct {
        __be16 port;
    } sctp;
    struct {
        __be16 key;	/* GRE key is 32bit, PPtP only uses 16bit */
    } gre;
};

// manipulable
struct nf_conntrack_man {
    union nf_inet_addr u3;
    union nf_conntrack_man_proto u;
    u_int16_t l3num;
};

// 該結構包含用來辨識連線的資訊
struct nf_conntrack_tuple {
    // 可變的部分
    struct nf_conntrack_man src; // source 

    // 下方固定不變
    // tuple = (port, protocol, direction)
    struct {
        union nf_inet_addr u3;
        // 多種不同的 protocol
        union {
            __be16 all;

            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                u_int8_t type, code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;

        /* The protocol. */
        u_int8_t protonum;

        /* The direction (for tuplehash) */
        u_int8_t dir;
    } dst; // 根據 member name，可以猜到這些資料都被用來辨識 destination
};
```

- tuple 定義了單向的 flow - a `tuple` is a structure containing the information to uniquely identify a connection. ie. if two packets have the same tuple, they are in the same connection; if not, they are not

- 並且因為 NAT，因此 kernel 將 tuple 拆成 manipulatable (縮寫為 man) 與 non-manipulatable

- Example:

  - `dst.protonum` - protocol type
    - 根據 type enum，protocl 目前看起來只支援 TCP、UDP、ICMP、DCCP、SCTP、GRE
    - connection tracking 大多使用 L4 (port) 的資訊來做 hash，而 ICMP 為 L3，只有 ip 資訊，但實際上還是會用 type 跟 code 來 hash

  - `src.u3.ip` - src ip
  - `dst.u3.ip` - dst ip
  - `src.u.udp.port` - src port
  - `dst.u.udp.port` - dst port



使用 connection tracking 時需要定義的結構 (include/net/netfilter/nf_conntrack_l4proto.h)：

```c
// L4 為應用層
struct nf_conntrack_l4proto {
    /* L4 Protocol number. */
    u_int8_t l4proto;

    // ...

    /* called by gc worker if table is full */
    // table 滿時呼叫的 gc handler
    bool (*can_early_drop)(const struct nf_conn *ct);

    // ...
};
```

- 內部有許多 function pointer，都需要由各協議自行實作



定義一個 flow 的結構 (include/net/netfilter/nf_conntrack.h)：

```c
// hash table entry 的結構，而一個連線會有兩個 hash table entry，雙向各一個
struct nf_conntrack_tuple_hash {
    struct hlist_nulls_node hnnode;
    struct nf_conntrack_tuple tuple;
};

struct nf_conntrack {
	refcount_t use;
};

struct nf_conn {
    // refcnt
    struct nf_conntrack ct_general;
	// ...
    // conntrack table entry
    // (IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY) 兩個 tuple
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    unsigned long status;
	// ...
};

// 各式各樣的狀態
enum ip_conntrack_status {
    IPS_EXPECTED      = (1 << IPS_EXPECTED_BIT),
    IPS_SEEN_REPLY    = (1 << IPS_SEEN_REPLY_BIT),
    // ...
};
```

- 用 key (hash): value 的方式儲存，而 value 則是 `struct nf_conntrack_tuple_hash`
- netfilter 中每個 flow 都被稱為一個 connection，用 `nf_conn` 來紀錄



對重要的 function 做初步介紹：

- `hash_conntrack_raw(tuple)` - 給 tuple 算一個 hash value
- `nf_conntrack_in()` (net/netfilter/nf_conntrack_core.c) - core function，packet 進入 connection tracking 的地方
  - 由 `ipv4_conntrack_in()` 進入，在 `ipv4_conntrack_ops[]` 被使用
  - 呼叫 `resolve_normal_ct()` --> `init_conntrack()` - allocate a new conntrack
    - `ct = __nf_conntrack_alloc(...)` - 建立新的 `struct nf_conn` 並初始化
      - 從 nf_conntrack_cachep 拿 object
- `nf_conntrack_confirm()` - 確認連線是否成功，return `NF_DROP` 代表封包要被丟棄
  - `__nf_conntrack_confirm()`



執行到 `nf_conntrack_in()` 時代表開始執行 connection tracking

- 在 `PRE_ROUTING` 或 `LOCAL_OUT` 建立新的連線紀錄，並將 conntrack entry 放到 unconfirmed list 當中
  - `PRE_ROUTING` - 是進來的第一個 hook
  - `LOCAL_OUT` - 是出去的第一個 hook

`nf_conntrack_confirm()` 負責驗證連線是否合法

- 會在 `POST_ROUTING` 或 `LOCAL_IN` 時，將 conntrack entry 放到 confirmed list 當中
- 兩種 hook 都是 packet 組離開 netfilter 的最後一個 hook



handler 是怎麼註冊到 netfilter 的：

```c
static const struct nf_hook_ops ipv4_conntrack_ops[] = {
    {
        .hook		= ipv4_conntrack_in,
        .pf		= NFPROTO_IPV4,
        .hooknum	= NF_INET_PRE_ROUTING,
        .priority	= NF_IP_PRI_CONNTRACK,
    },
    {
        .hook		= ipv4_conntrack_local,
        .pf		= NFPROTO_IPV4,
        .hooknum	= NF_INET_LOCAL_OUT,
        .priority	= NF_IP_PRI_CONNTRACK,
    },
    {
        .hook		= ipv4_confirm,
        .pf		= NFPROTO_IPV4,
        .hooknum	= NF_INET_POST_ROUTING,
        .priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
    },
    {
        .hook		= ipv4_confirm,
        .pf		= NFPROTO_IPV4,
        .hooknum	= NF_INET_LOCAL_IN,
        .priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
    },
};
```

`nf_conntrack_in()` source code 分析：

```c
unsigned int
    nf_conntrack_in(struct sk_buff *skb, const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct, *tmpl;
    u_int8_t protonum;
    int dataoff, ret;

    tmpl = nf_ct_get(skb, &ctinfo); // 根據 skb 取得 conntrack info (ctinfo)
    // 紀錄在或是不需要 track
    if (tmpl || ctinfo == IP_CT_UNTRACKED) {
        // 之前看過就直接忽略 (loopback or untracked)
        if ((tmpl && !nf_ct_is_template(tmpl)) ||
            ctinfo == IP_CT_UNTRACKED)
            return NF_ACCEPT;
        // 不 ignore --> counter 設 0
        skb->_nfct = 0;
    }

    // 取得 L4 protocol info
    dataoff = get_l4proto(skb, skb_network_offset(skb), state->pf, &protonum);

    // ICMP 需要特別處理 (?)
    if (protonum == IPPROTO_ICMP || protonum == IPPROTO_ICMPV6) {
        ret = nf_conntrack_handle_icmp(tmpl, skb, dataoff,
                                       protonum, state);
        // ...
    }
    
repeat:
    // 開始 conntrack，取得 tuple 後建立/更新連接狀態
    ret = resolve_normal_ct(tmpl, skb, dataoff,
                            protonum, state);
	// ...
    ct = nf_ct_get(skb, &ctinfo);
    // 處理各種不同 procotol 的 packet
    ret = nf_conntrack_handle_packet(ct, skb, dataoff, ctinfo, state);
    if (ret <= 0) {
        nf_ct_put(ct);
        skb->_nfct = 0;
        // 特殊情況： TCP 嘗試 reopen 已經關閉的連線
        if (ret == -NF_REPEAT)
            goto repeat;
		// ...
    }
out:
    // ...
    return ret;
}
```

所以關於 conntrack 紀錄的初始化與更新都做在 `resolve_normal_ct()`，下面看一下他的 source code：

```c
static int
    resolve_normal_ct(struct nf_conn *tmpl,
                      struct sk_buff *skb,
                      unsigned int dataoff,
                      u_int8_t protonum,
                      const struct nf_hook_state *state)
{
    const struct nf_conntrack_zone *zone;
    struct nf_conntrack_tuple tuple;
    struct nf_conntrack_tuple_hash *h;
    enum ip_conntrack_info ctinfo;
    struct nf_conntrack_zone tmp;
    u32 hash, zone_id, rid;
    struct nf_conn *ct;

    // 嘗試取得 tuple
	nf_ct_get_tuple(skb, skb_network_offset(skb),
                         dataoff, state->pf, protonum, state->net,
                         &tuple);

    // 與過去的 tuple 相比，看起來 tuple 都會存到名稱叫 "zone" 的地方
    zone = nf_ct_zone_tmpl(tmpl, skb, &tmp);
    zone_id = nf_ct_zone_id(zone, IP_CT_DIR_ORIGINAL);
    // 將 zone_id 與 tuple 算出 hash
    hash = hash_conntrack_raw(&tuple, zone_id, state->net);
    // 取得 tuple 的 conntrack table entry
    h = __nf_conntrack_find_get(state->net, zone, &tuple, hash);
	// ...
	// 找不到，代表連線是新的，分配新的 conntrack table entry
    if (!h) {
        h = init_conntrack(state->net, tmpl, &tuple,
                           skb, dataoff, hash);
        // ...
    }
    ct = nf_ct_tuplehash_to_ctrack(h);
   	// ...
    // 更新 ctrack 的狀態
    nf_ct_set(skb, ct, ctinfo);
    return 0;
}
```

`init_conntrack()` 如何初始化 ctrack 結構的：

```c
static noinline struct nf_conntrack_tuple_hash *
init_conntrack(struct net *net, struct nf_conn *tmpl,
	       const struct nf_conntrack_tuple *tuple,
	       struct sk_buff *skb,
	       unsigned int dataoff, u32 hash)
{
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conntrack_tuple repl_tuple;
	struct nf_conntrack_expect *exp = NULL;
	const struct nf_conntrack_zone *zone;
	struct nf_conn_timeout *timeout_ext;
	struct nf_conntrack_zone tmp;
	struct nf_conntrack_net *cnet;

	// 取得存在的 zone
	zone = nf_ct_zone_tmpl(tmpl, skb, &tmp);
    // 從 conntrack table 中分配一個 entry
	ct = __nf_conntrack_alloc(net, zone, tuple, &repl_tuple, GFP_ATOMIC,
				  hash);
	// 與 extension 相關的一些處理
	// ...
	if (cnet->expect_count) {
        // disable interrupt and get lock
		spin_lock_bh(&nf_conntrack_expect_lock);
		exp = nf_ct_find_expectation(net, zone, tuple);
        // 對於 expectation (?) 的處理
		if (exp) {
			// ...
		}
        // enable interrupt and release lock
		spin_unlock_bh(&nf_conntrack_expect_lock);
	}
	// ...

	/* Other CPU might have obtained a pointer to this object before it was
	 * release
	 */
	smp_wmb();

    // 將 ctrack 與 sk_buff 做聯繫
	refcount_set(&ct->ct_general.use, 1);
	return &ct->tuplehash[IP_CT_DIR_ORIGINAL];
}
```

`__nf_conntrack_alloc()` internal：

```c
static struct nf_conn *
    __nf_conntrack_alloc(struct net *net,
                         const struct nf_conntrack_zone *zone,
                         const struct nf_conntrack_tuple *orig,
                         const struct nf_conntrack_tuple *repl,
                         gfp_t gfp, u32 hash)
{
    struct nf_conntrack_net *cnet = nf_ct_pernet(net);
    unsigned int ct_count;
    struct nf_conn *ct;
    // ...

    // 分配 ctrack instance
    ct = kmem_cache_alloc(nf_conntrack_cachep, gfp);
    spin_lock_init(&ct->lock);
    ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple = *orig; // src
    ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode.pprev = NULL;
    ct->tuplehash[IP_CT_DIR_REPLY].tuple = *repl; // dst
	// 紀錄 hash value
    *(unsigned long *)(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev) = hash;
    ct->status = 0;
    WRITE_ONCE(ct->timeout, 0);
    write_pnet(&ct->ct_net, net);
    memset_after(ct, 0, __nfct_init_offset);
	// 將 ct 加到 zone 裡面
    nf_ct_zone_add(ct, zone);

	// ...
    return ct;
}
```

`nf_conntrack_confirm()` 確定 packet 是否被丟棄：

```c
static inline int nf_conntrack_confirm(struct sk_buff *skb)
{
	struct nf_conn *ct = (struct nf_conn *)skb_nfct(skb);
	int ret = NF_ACCEPT;

	if (ct) {
		if (!nf_ct_is_confirmed(ct)) {
            // 關鍵在 __nf_conntrack_confirm
			ret = __nf_conntrack_confirm(skb);

			if (ret == NF_ACCEPT)
				ct = (struct nf_conn *)skb_nfct(skb);
		}
		// ...
	}
	return ret;
}
```

- `skb_nfct()` - 取得 `skb->_nfct`
- ct 可以從 skb 來，而 net 與 zone 則是從 ct 來

`__nf_conntrack_confirm()` 為 confirm 的主要邏輯：

```c
int
__nf_conntrack_confirm(struct sk_buff *skb)
{
	unsigned int chainlen = 0, sequence, max_chainlen;
	const struct nf_conntrack_zone *zone;
	unsigned int hash, reply_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct hlist_nulls_node *n;
	enum ip_conntrack_info ctinfo;
	struct net *net;
	int ret = NF_DROP;

	ct = nf_ct_get(skb, &ctinfo);
	net = nf_ct_net(ct);
	zone = nf_ct_zone(ct);
    
    // disable interrupt
	local_bh_disable();

	do {
        // 取得新的 hash value
		hash = *(unsigned long *)&ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev;
		hash = scale_hash(hash);
		reply_hash = hash_conntrack(net,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple,
					   nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_REPLY));
	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

    // 將 ct 的狀態設成 confirmed
	ct->status |= IPS_CONFIRMED;
	
	// 對於 race condition 做了很多處理
    // ...
    
	__nf_conntrack_insert_prepare(ct);
	__nf_conntrack_hash_insert(ct, hash, reply_hash);
	nf_conntrack_double_unlock(hash, reply_hash);
    
    // enable interrupt
	local_bh_enable();
	// ...
	return NF_ACCEPT;
}
```

- `nf_conntrack_hash` 為 global variable，應該是 hash table



梳理一下執行流程：

`nf_conntrack_in()` - hook 的進入點，目前只會有 socket buffer 結構 (skb)

- 取出 `nf_conn` (skb->nfct)，並檢查是否存在，
- `resolve_normal_ct()` 只會檢查並設置一些成員，或是為新的連線建立 cf
  - `nf_ct_get_tuple()` 根據 skb 的 member 來初始化 local variable `tuple`
  - 沒有開啟 `CONFIG_NF_CONNTRACK_ZONES`，zone 只會是 `&nf_ct_zone_dflt`，zone id 則是 `NF_CT_DEFAULT_ZONE_ID`
  - `hash_conntrack_raw()` 會根據 zone_id 以及連線資訊 (src, dst, dport) 與 random value 產生一個 hash
  - `init_conntrack()` - 分配與初始化 ct 結構
    - `nf_ct_invert_tuple()` 依據 tuple 建立一個相反的 tuple (reply tuple)
    - `__nf_conntrack_alloc()` 從 nf_conntrack_cachep 取得一個 ct object，並將 tuple 的相關資料寫到 ct (`struct nf_conn`) 內
    - `nf_ct_set()` - 綁定 nf 到 skb 上 (init `skb->nfct`)
- `nf_conntrack_handle_packet()` 處理不同 protocol 的封包，本質上就是在紀錄/更新 packet 的資訊



### NAT Source tracing

Hook 的優先順序：Conntrack > NAT > Packet Filtering

`nf_nat_inet_fn()` (net/netfilter/nf_nat_core.c) 

- 從 `nf_nat_ipv4_fn()` 呼叫，而此 function 又被 `nf_nat_ipv4_pre_routing()`、`nf_nat_ipv4_local_in()`、`nf_nat_ipv4_out()`、`nf_nat_ipv4_local_fn()` 呼叫

```c
unsigned int
nf_nat_inet_fn(void *priv, struct sk_buff *skb,
	       const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(state->hook);

	ct = nf_ct_get(skb, &ctinfo);
    // 沒有 ct 就不能做 NAT，因此 NAT 的優先度位於 ct 之後
	if (!ct || in_vrf_postrouting(state))
		return NF_ACCEPT;

	nat = nfct_nat(ct);

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
	case IP_CT_NEW:
		if (!nf_nat_initialized(ct, maniptype)) {
			struct nf_nat_lookup_hook_priv *lpriv = priv;
            // 取得 NAT 的 rule
			struct nf_hook_entries *e = rcu_dereference(lpriv->entries);
			unsigned int ret;
			int i;
			// 沒有規則
			if (!e)
				goto null_bind;

            // 依序執行每個 hook
			for (i = 0; i < e->num_hook_entries; i++) {
				ret = e->hooks[i].hook(e->hooks[i].priv, skb,
						       state);
				if (ret != NF_ACCEPT) // 不是 accept 就馬上 return
					return ret;
				if (nf_nat_initialized(ct, maniptype))
					goto do_nat;
			}
null_bind:
			ret = nf_nat_alloc_null_binding(ct, state->hook);
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			// ...
		}
		break;
	default:
		/* ESTABLISHED */
		// ...
	}
do_nat:
    // accept 就會走到此
	return nf_nat_packet(ct, ctinfo, state->hook, skb);

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}
```

- 如果 skb 狀態是 `IP_CT_RELATED`、`IP_CT_RELATED_REPLY` 或 `IP_CT_NEW`，就會執行對應 NAT rule 的每個 hook

`nf_nat_packet()` 會根據 `nf_nat_setup_info` 對封包做處理：

```c
unsigned int nf_nat_packet(struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo,
			   unsigned int hooknum,
			   struct sk_buff *skb)
{
	enum nf_nat_manip_type mtype = HOOK2MANIP(hooknum);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int verdict = NF_ACCEPT;
	unsigned long statusbit;

	if (mtype == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;
	else
		statusbit = IPS_DST_NAT;
    
    // invert if reply
	if (dir == IP_CT_DIR_REPLY)
		statusbit ^= IPS_NAT_MASK;

	/* Non-atomic: these bits don't change. */
	if (ct->status & statusbit)
		verdict = nf_nat_manip_pkt(skb, ct, mtype, dir);

	return verdict;
}
```

`nf_nat_manip_pkt()` 調整了 L3 的 packet information：

 ```c
 unsigned int nf_nat_manip_pkt(struct sk_buff *skb, struct nf_conn *ct,
                               enum nf_nat_manip_type mtype,
                               enum ip_conntrack_dir dir)
 {
     struct nf_conntrack_tuple target;
 
     /* We are aiming to look like inverse of other direction. */
     nf_ct_invert_tuple(&target, &ct->tuplehash[!dir].tuple);
 
     switch (target.src.l3num) {
         case NFPROTO_IPV6:
             if (nf_nat_ipv6_manip_pkt(skb, 0, &target, mtype))
                 return NF_ACCEPT;
             break;
         case NFPROTO_IPV4:
             if (nf_nat_ipv4_manip_pkt(skb, 0, &target, mtype))
                 return NF_ACCEPT;
             break;
         default:
             WARN_ON_ONCE(1);
             break;
     }
 
     return NF_DROP;
 }
 ```



### 其他

- Docker 預設使用的 `bridge` 會對每個 container 分配一個 private network，但在出去 host 時就會需要 NAT，將 private IP 轉換成 host IP
- 可以將 conntrack 視為有狀態的 firewall



### 參考資料

- https://veritas501.github.io/2022_08_02-CVE-2022-34918%20netfilter%20%E5%88%86%E6%9E%90%E7%AC%94%E8%AE%B0/

- https://arthurchiao.art/blog/deep-dive-into-iptables-and-netfilter-arch-zh/

  https://arthurchiao.art/blog/conntrack-design-and-implementation-zh/
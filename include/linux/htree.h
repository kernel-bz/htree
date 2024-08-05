// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Hash-Trees header
 *  lib/htree.h
 *
 *  Copyright(C) 2024, JaeJoon Jung <rgbi3307@gmail.com> 
 */

#ifndef _LINUX_HTREE_H
#define _LINUX_HTREE_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

/*
 size of one hash tree struct: [16]Bytes
 size of one data struct: (40)Bytes
 size of middle: 32Bytes

 if system has 16GB memory, number of index(nr) is 256M(middle)
 if system has  4GB memory, number of index(nr) is  64M(middle)
 ...
 index max: 1 << 50: 2^50:   1P (  1P x 32:  32P) --> depth:6 (64bits index)
 index max: 1 << 40: 2^40:   1T (  1T x 32:  32T) --> depth:6 (64bits index)
 ...
 index max: 1 << 32: 2^32:   4G (  4G x 32: 128G) --> depth:5
 index max: 1 << 28: 2^29: 512M (512M x 32:  16G) --> depth:4 (32bits index)
 index max: 1 << 28: 2^28: 256M (256M x 32:   8G) --> depth:4
 index max: 1 << 26: 2^26:  64M ( 64M x 32:   2G) --> depth:3 (32bits index)
 index max: 1 << 25: 2^25:  32M ( 32M x 32:   1G) --> depth:2

 if number of index(nr) is between 32M and 64M, hash tree depth is [2,3)

 hash array size(anum): 1 << (sbit - depth)
 dnum: [d0:anum x d1:anum x d2:anum x d3:anum x d4:anum x d5:anum ...)

 if starting hash bit(sbit) is 9:
 dnum: [d0:512  x d1:256  x d2:128  x d3:64   x d4:32   x d5:16   ...)

 dcnt(max index): (d:dnum * HTREE_NODE_CNT): (dnum * 4)
     : d0:2K, d1:512K, d2:64M, d3:4G, d4:128G, d5:2T, ...

 asum(mid index): (d:dnum * HTREE_NODE_MIN): (dnum * 2)
     : d0:1K, d1:256K, d2:32M, d3:2G, d4: 64G, d5:1T, ...

 htree depth avg(d): (3)
 hlist node cnt(c) : [4)
 algorithm O(n)    : (d) x c == 3 x 4 == 12 (finding walks)
 memory efficiency : (dcnt / asum) == 85%(/100 == 0.85) (usage eff)

 htree depth(d):   0 ---->   1 ---->   2 ---->  3 ---->  4 ---->  5
 hash bits(b)  :   9 ---->   8 ---->   7 ---->  6 ---->  5 ---->  4
 table size(t) : 512 ----> 256 ----> 128 ----> 64 ----> 32 ----> 16

 d0:b9:t512
    +-----[4)--> d1:b8:t256
		    +-------> d2:b7:t128
				 +-------> d3:b6:t64
					      +------> d4:b5:t32
							  +------> d5:b4:t16

 if sort flag is HTREE_FLAG_ASCD, first htree depth(d0) has smallest index.
 if sort flag is HTREE_FLAG_DECD, first htree depth(d0) has largest index.
 hts->most has the hash key position, algorithm O(1).

 If there is the same index:
 if req is htf_ins, the new udata is inserted next to each other.
 if req is htf_erase, the new udata is inserted, and old udata is erased.
*/

struct hash_tree {		/* *htree: hash tree struct */
	struct hlist_head head;	/* head of hash list(include/linux/types.h) */
	struct hash_tree *next;	/* next depth hash tree of this node */
} __aligned(16);		/* size:16, must be aligned(2^4) */


struct htree_data {		/* *hdata: to interface with data */
	u64 index;		/* hash index to interface with hash key */
	struct hlist_node hnode;/* hash list node(data) to connect udata */
};


struct htree_state {		/* *hts: hash tree state to operation */
	s8  sbit;		/* start bits of hash table */
	s8  dept;		/* depth[0...127] of hash tree */
	s8  dmax;		/* max depth[0...127] of hash tree */
	u16 hkey;		/* hash key */
	u16 wcnt;		/* count of finding walk steps */
	u16 most;		/* moset smallest or largest position */
	s32 acnt;		/* global: count of hash table alloc */
	u64 dcnt;		/* global: count of data alloc */
	u64 asum;		/* global: sum of hash table slot(anum) */
	u8  idxt: 1;		/* bit flag: index type [0:64bits, 1:32bits] */
	u8  sort: 1;		/* bit flag: sort type [0:ascend. 1:descend] */
} __packed;


enum ht_flags {			/* htf: htree working flags (keep order) */
	htf_none,
	htf_ok,
	htf_ins,		/* insert */
	htf_find_lt,		/* find less than */
	htf_find,		/* find */
	htf_find_gt,		/* find grater than */
	htf_move,
	htf_update,
	htf_erase,
	htf_freed,
};

struct htree_root {				/* root: hash tree root */
	spinlock_t		ht_lock;	/* lock while update */
	struct hash_tree __rcu 	*ht_first;	/* start of the hash tree */
};

#define DEFINE_HTREE_ROOT(name)					\
	struct htree_root name = { 				\
		.ht_lock = __SPIN_LOCK_UNLOCKED(name.ht_lock),	\
		.ht_first = NULL,				\
	}

#define HTREE_BITS_START	8	/* start of hash bits(default) */
#define HTREE_BITS_END		3	/* end of hash bits */
#define HTREE_BITS_SHIFT	3	/* shift of hash bits */

#define HTREE_NODE_MIN		2	/* node min in one slot of htree */
#define HTREE_NODE_CNT		4	/* node count in one slot of htree */
#define HTREE_NODE_MAX		6	/* node max(2^4 - 2) in one slot */

#define HTREE_GOLDEN_NR		25

/*
 * htgr32: hash tree golden ratio for 32bits: Standard Deviation: sqrt(4)
 */
static const u32 htgr32[] = { GOLDEN_RATIO_32,
	0x8864761C, 0x64761C6B, 0x864761C6, 0x761C6B07,
	0x4761C6B0, 0x1C6B0718, 0x61C6B071, 0x6B0718E0,
	0xC6B0718E, 0x0718E074, 0xB0718E07, 0x18E074B3,
	0x718E074B, 0xE074B396, 0x8E074B39, 0x74B396CC,
	0x074B396C, 0xB396CC6B, 0x4B396CC6, 0x96CC6B07,
	0x396CC6B0, 0xCC6B0718, 0x6CC6B071, 0x1C88647E
};

/*
 * htgr64: hash tree golden ratio for 64bits: Standard Deviation: sqrt(4)
 */
static const u64 htgr64[] = { GOLDEN_RATIO_64,
	0xB481B860C486B468ull, 0x4080B581D962C816ull, 0x86C281B581B061D4ull,
	0xCB64C8B64D80B283ull, 0xC680C584DB60C8A1ull, 0x0C8262682B5862B6ull,
	0x4B2B61B82616801Cull, 0x5680D518CB61C0B1ull, 0x1584CB61C816468Cull,
	0x0B280CB60B816D68ull, 0x64680B1938B62B18ull, 0x84B261B0864180B5ull,
	0x8064680B0938B61Cull, 0x583CB61C4C64280Bull, 0x680B282DB6D1C864ull,
	0x51864180B481AB4Dull, 0x2BB080CB64C8D6A1ull, 0xA24680B180CB61D9ull,
	0xC82D4680B082CA61ull, 0x80B583A461C28646ull, 0x2C460C8064D80B58ull,
	0xA5C461C8064680C2ull, 0x1864A80B583C26BCull, 0xCB583CB6E2806064ull
};

#define HTREE_HASH_KEY(idx, d, bits)	( sizeof(idx) <= 4 ?	\
	(((u32)idx + d) * htgr32[d]) >> (32 - bits) : 		\
	(((u64)idx + d) * htgr64[d]) >> (64 - bits) )

#define HTREE_MAX_NCNT(dept)	\
	((dept < HTREE_NODE_MIN) ? HTREE_NODE_CNT : HTREE_NODE_MAX)

#define HTREE_ARRAY_SIZE(bits)		(1 << bits)
#define HTREE_EFF_ASUM(asum)		(asum * HTREE_NODE_MIN)
#define HTREE_EFFICIENCY(dcnt, asum)	((dcnt * 100) / HTREE_EFF_ASUM(asum))

#define HTREE_IDX_BASIC_NR		(1 << 25)	/* default: 32M */

/* flag bit in the htree_state struct */
#define HTREE_FLAG_IDX64	0
#define HTREE_FLAG_IDX32	1
#define HTREE_FLAG_ASCD		0
#define HTREE_FLAG_DECD		1

/* node count [0...255] to set/get at htree->next */
#define HTREE_NCNT_MASK		0xF

static inline struct hash_tree *ht_ncnt_inc(struct hash_tree *ht, u8 ncnt)
{
	return (struct hash_tree *)((u64)ht + ncnt);
}

static inline struct hash_tree *ht_ncnt_dec(struct hash_tree *ht, u8 ncnt)
{
	return (struct hash_tree *)((u64)ht - ncnt);
}

static inline struct hash_tree *ht_ncnt_set(struct hash_tree *ht, u8 ncnt)
{
	return (struct hash_tree *)(((u64)ht & ~HTREE_NCNT_MASK) | ncnt);
}

static inline u8 ht_ncnt_get(struct hash_tree *ht)
{
	return (u8)((u64)ht & HTREE_NCNT_MASK);
}

static inline struct hash_tree *ht_ncnt_pointer(struct hash_tree *ht)
{
	return (struct hash_tree *)((u64)ht & ~HTREE_NCNT_MASK);
}

static inline u8 ht_bits_from_depth(s8 sbit, s8 depth)
{
	s8 diff;
	diff = sbit - depth;
	return (diff < HTREE_BITS_END) ? HTREE_BITS_END : diff;
}

static inline u16 ht_get_hkey(u64 index, s8 dept, u8 bits, u8 idxt)
{
	return (idxt == HTREE_FLAG_IDX32) ?
		HTREE_HASH_KEY((u32)index, dept % HTREE_GOLDEN_NR, bits):
		HTREE_HASH_KEY((u64)index, dept % HTREE_GOLDEN_NR, bits);
}

/**
  * htree_add - add an object to a hashtree
  * @hashtree: hashtree to add to
  * @node: the &struct hlist_node of the object to be added
  * @key: the hash key of the object to be added
  */
#define htree_add_head(hashtree, node, key)	\
	hlist_add_head((struct hlist_node*)node, &hashtree[key].head)


/* public functions in the lib/htree.c */
struct hash_tree *ht_table_alloc(struct htree_state *hts);

struct htree_state *ht_hts_alloc(void);

void ht_hts_clear_init(struct htree_state *hts, u64 maxnr, u8 idxt, u8 sort);

struct htree_data *ht_find(struct htree_state *hts, 
			   struct hash_tree *htree, u64 index);

struct htree_data *ht_insert(struct htree_state *hts, struct hash_tree *htree,
			     struct htree_data *hdata, enum ht_flags htf_req);

struct htree_data *ht_erase(struct htree_state *hts,
			    struct hash_tree *htree, u64 index);

enum ht_flags ht_destroy_lock(struct htree_state *hts, struct htree_root *root);

void ht_statis(struct htree_state *hts, struct hash_tree *htree,
	       s32 *acnt, u64 *dcnt);

struct htree_data *ht_most_index(struct htree_state *hts, 
				 struct hash_tree *htree);

/* spin_lock API */
#define ht_trylock(xa)          spin_trylock(&(xa)->ht_lock)
#define ht_lock(xa)             spin_lock(&(xa)->ht_lock)
#define ht_unlock(xa)           spin_unlock(&(xa)->ht_lock)
#define ht_lock_bh(xa)          spin_lock_bh(&(xa)->ht_lock)
#define ht_unlock_bh(xa)        spin_unlock_bh(&(xa)->ht_lock)
#define ht_lock_irq(xa)         spin_lock_irq(&(xa)->ht_lock)
#define ht_unlock_irq(xa)       spin_unlock_irq(&(xa)->ht_lock)
#define ht_lock_irqsave(xa, flags) \
                                spin_lock_irqsave(&(xa)->ht_lock, flags)
#define ht_unlock_irqrestore(xa, flags) \
                                spin_unlock_irqrestore(&(xa)->ht_lock, flags)
#define ht_lock_nested(xa, subclass) \
                                spin_lock_nested(&(xa)->ht_lock, subclass)
#define ht_lock_bh_nested(xa, subclass) \
                                spin_lock_bh_nested(&(xa)->ht_lock, subclass)
#define ht_lock_irq_nested(xa, subclass) \
                                spin_lock_irq_nested(&(xa)->ht_lock, subclass)
#define ht_lock_irqsave_nested(xa, flags, subclass) \
                spin_lock_irqsave_nested(&(xa)->ht_lock, flags, subclass)


static inline void htree_root_alloc(struct htree_state *hts,
		struct htree_root *root)
{
	rcu_assign_pointer(root->ht_first, ht_table_alloc(hts));
}

static inline struct hash_tree *htree_first_rcu(const struct htree_root *root)
{
	return rcu_dereference_check(root->ht_first,
			lockdep_is_held(&root->ht_lock));
}

static inline struct hash_tree *htree_first_rcu_locked(const struct htree_root *root)
{
	return rcu_dereference_protected(root->ht_first,
			lockdep_is_held(&root->ht_lock));
}


static inline __must_check struct htree_data *ht_insert_lock(
		struct htree_state *hts, struct htree_root *root,
		struct htree_data *hdata, enum ht_flags req)
{
	ht_lock(root);
	hdata = ht_insert(hts, htree_first_rcu_locked(root), hdata, req);
	ht_unlock(root);
	return hdata;
}

static inline __must_check struct htree_data *ht_insert_lock_irq(
		struct htree_state *hts, struct htree_root *root,
		struct htree_data *hdata, enum ht_flags req)
{
	ht_lock_irq(root);
	hdata = ht_insert(hts, htree_first_rcu_locked(root), hdata, req);
	ht_unlock_irq(root);
	return hdata;
}

static inline __must_check struct htree_data *ht_insert_lock_irqsave(
		struct htree_state *hts, struct htree_root *root,
		struct htree_data *hdata, enum ht_flags req)
{
	unsigned long flags;
	ht_lock_irqsave(root, flags);
	hdata = ht_insert(hts, htree_first_rcu_locked(root), hdata, req);
	ht_unlock_irqrestore(root, flags);
	return hdata;
}

static inline __must_check struct htree_data *ht_erase_lock(
		struct htree_state *hts, struct htree_root *root, u64 index)
{
	struct htree_data *hdata;
	ht_lock(root);
	hdata = ht_erase(hts, htree_first_rcu_locked(root), index);
	ht_unlock(root);
	return hdata;
}

static inline __must_check struct htree_data *ht_erase_lock_irq(
		struct htree_state *hts, struct htree_root *root, u64 index)
{
	struct htree_data *hdata;
	ht_lock_irq(root);
	hdata = ht_erase(hts, htree_first_rcu_locked(root), index);
	ht_unlock_irq(root);
	return hdata;
}

static inline __must_check struct htree_data *ht_erase_lock_irqsave(
		struct htree_state *hts, struct htree_root *root, u64 index)
{
	unsigned long flags;
	struct htree_data *hdata;
	ht_lock_irqsave(root, flags);
	hdata = ht_erase(hts, htree_first_rcu_locked(root), index);
	ht_unlock_irqrestore(root, flags);
	return hdata;
}

#endif	/* _LINUX_HTREE_H */

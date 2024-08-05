// SPDX-License-Identifier: GPL-2.0-only
/*
 *  htree/htree-test.c
 *  Hash-Trees test codes to verify
 *
 *  Copyright(C) 2024, JaeJoon Jung <rgbi3307@gmail.com>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/sched.h>

#include <linux/htree.h>

/*
	Hash Tree API flow
	------------------

	DEFINE_HTREE_ROOT(ht_root);		//define htree_root

	*hts = ht_hts_alloc();			//alloc hts
	ht_hts_clear_init(hts, ...);

	htree_root_alloc(hts, &ht_root);	//alloc first hash tree

	run_loop() {

		*udata = _data_alloc(index);	//alloc udata

		ht_insert_lock(hts, &ht_root, udata->hdata, ..);
		ht_erase_lock(hts, &ht_root, index);
		hdata = ht_find(hts, ht_root.ht_first, index);
		hdata = ht_most_index(hts, ht_root.ht_first);

		ht_statis(hts, ht_root.ht_first, ...);
	}

	htree_erase_all_lock(hts, &ht_root)	//remove all udata

	ht_destroy_lock(hts, &ht_root)		//remove all htree

	kfree(hts)				//remove hts
*/


/*
#define HTREE_DEBUG_INFO
#define HTREE_DEBUG_DETAIL
*/

#define pr_ht_err		pr_err
#define pr_ht_warn		pr_warn
#define pr_ht_stat		printk

#ifdef HTREE_DEBUG_INFO
#define pr_ht_info		printk

#else
#define pr_ht_info(fmt, ...)

#endif

#ifdef HTREE_DEBUG_DETAIL
#define pr_ht_find		printk
#define pr_ht_erase		printk
#define pr_ht_update		printk
#define pr_ht_debug		printk

#else
#define pr_ht_find(fmt, ...)
#define pr_ht_erase(fmt, ...)
#define pr_ht_update(fmt, ...)
#define pr_ht_debug(fmt, ...)

#endif

#define HTREE_TEST_SCHED_CNT	200

DEFINE_HTREE_ROOT(ht_root);

struct data_struct {
	/* user defined data members ... */
	char a;
	int  b;
	long c;

	/* must be here to interface hash index */
	struct htree_data hdata;
};

/**
 * _htree_data_alloc - memory allocation of user data_struct
 * @index: 64bits index to make hash key
 *
 * the hash key is created using the index and connected to the hash tree.
 * udata is linked to the index(hash key) location.
 *
 * connection flow:
 * udata <----> hdata <----> htree
 * index(64bits): udata.hdata.index --> hash key --> hash table index(htree)
 * data : udata.hdata.hnode --> htree.head --> hash list data nodes
 */
static struct data_struct *_htree_data_alloc(u64 index)
{
	struct data_struct *udata = (struct data_struct *)
			kmalloc(sizeof(struct data_struct), GFP_KERNEL);

	/* todo: set user defined data */
	udata->a = 97;
	udata->b = 98;
	udata->c = 99;

	/* interface with hash index (64bits) */
	udata->hdata.index = index;

	INIT_HLIST_NODE(&udata->hdata.hnode);

	return udata;
}

/**
 * _htree_test_hash_var - calculate the standard deviation of the hash key
 * @bits: hash table size is (1 << bits)
 * @vbits: for loop count
 *
 * ht_get_hkey distributes the hash keys using a golden ratio table.
 */
static void _htree_hash_dev(const u32 bits, const u32 vbits)
{
	u64 i, v, k;
	s64 ka;
	u64 ks, kas = 0;
	const u16 kcnt = 1 << bits;
	u32 *kc = (u32 *)kmalloc_array(kcnt, sizeof(u32), GFP_KERNEL);

	const u32 vcnt = 1 << vbits;

	for (v = 0; v < vcnt; v++) {
		for (k = 0; k < kcnt; k++)
			kc[k] = 0;

		for (i = 0; i < HTREE_GOLDEN_NR; i++) {
			k = ht_get_hkey(v, i, bits, HTREE_FLAG_IDX32);
			kc[k]++;
			k = ht_get_hkey(v, i, bits, HTREE_FLAG_IDX64);
			kc[k]++;
		}

		ks = 0;
		for (k = 0; k < kcnt; k++)
			ks += kc[k];
		ka = ks >> bits;	/* avg: ks / kcnt */
		ks = 0;
		for (k = 0; k < kcnt; k++)
			ks += ((kc[k] - ka) * (kc[k] - ka));
		ka = ks >> bits;	/* Variance: avg: ks / kcnt */
		kas += ka;		/* sum of Variance */
	}
	/* Standard Deviation: sqrt(avg:kas) */
	pr_ht_info("vbits:%u, cnt:%u, Standard Deviation:sqrt(%llu)\n\n",
		   vbits, vcnt, (kas >> vbits) >> 2);
	kfree(kc);
}

/**
 * __htree_hash_key - outputs hash key distribution data
 * @index: index to make hash key
 * @bits: hash table size is (1 << bits)
 */
static void __htree_hash_key(u64 index, const u32 bits)
{
	u32 k, key0, key1, key2;
	const u32 kcnt = 1 << bits;
	u32 *kcnt0 = (u32*)kmalloc_array(kcnt, sizeof(u32), GFP_KERNEL);
	u32 *kcnt1 = (u32*)kmalloc_array(kcnt, sizeof(u32), GFP_KERNEL);
	u32 *kcnt2 = (u32*)kmalloc_array(kcnt, sizeof(u32), GFP_KERNEL);

	for (k = 0; k < kcnt; k++) {
		kcnt0[k] = 0;
		kcnt1[k] = 0;
		kcnt2[k] = 0;
	}

	key1 = index;
	for (k = 0; k < HTREE_GOLDEN_NR; k++) {
		key0 = hash_min(index, bits);
		key1 = hash_min((u64)key1, bits);
		kcnt0[key0]++;
		kcnt1[key1]++;

		key2 = ht_get_hkey(index, k, bits, HTREE_FLAG_IDX32);
		kcnt2[key2]++;
		key2 = ht_get_hkey(index, k, bits, HTREE_FLAG_IDX64);
		kcnt2[key2]++;
	}

	key0 = 0;
	key1 = 0;
	key2 = 0;
	for (k = 0; k < kcnt; k++) {
		pr_ht_info("%3u: kcnt0:%6u, kcnt1:%6u, kcnt2:%6u\n",
		       k, kcnt0[k], kcnt1[k], kcnt2[k]);
		key0 += kcnt0[k];
		key1 += kcnt1[k];
		key2 += kcnt2[k];
	}
	pr_ht_info("----------------------------------------------\n");
	pr_ht_info("sum: skey0:%6u, skey1:%6u, skey2:%6u\n", key0, key1, key2);

	kfree(kcnt0);
	kfree(kcnt1);
	kfree(kcnt2);
}

/**
 * _htree_hash_key - test of sample hash key
 * @bits: hash table size is (1 << bits)
 * @vbits: loop count in use sample index
 *
 * outputs hash key distribution data calculated from hash_min()
 *      and ht_get_hkey using some indices.
 */
static void _htree_hash_key(const u32 bits, const u32 vbits)
{
	u64 v;
	for (v = 0; v < vbits / 2; v++) {
		pr_ht_info("value:%llu, bits:%u\n", v, bits);
		pr_ht_info("----------------------------------------------\n");
		__htree_hash_key(v, bits);
		pr_ht_info("\n");
	}
}

/**
 * _htree_test_hash - hash key test
 *
 * output of hash key distribution
 */
static void _htree_test_hash(void)
{
	const u32 bits = 2;
	const u32 vbits = 12;

	_htree_hash_dev(bits, vbits);
	_htree_hash_key(bits, vbits);
}


#ifdef HTREE_DEBUG_DETAIL

/**
 * htree_hdata_debug - shows hlist nodes in the hash tree at same index order.
 * @htree: hash_tree to show
 * @index: index to find
 * @htf: ht_flags to confirm
 */
static void htree_debug_hdata(struct htree_state *hts, struct hash_tree *hcurr,
			      u64 index, enum ht_flags htf)
{
	u8 ncnt, bits;
	u16 key;
	s16 dept;
	u32 offset;
	struct htree_data *pos;
	struct hlist_node *tmp;
	const char *htfs[] = {
		"htf_none",
		"htf_ok",
		"htf_ins",
		"htf_find_lt",
		"htf_find",
		"htf_find_gt",
		"htf_move",
		"htf_update",
		"htf_erase",
		"htf_freed",
	};

	if (!hcurr)
		return;

	dept = hts->dept;
	pr_ht_debug("\n((%s)) DEBUG sbit:%u, dept:%d/%d, index:<%llu>\n",
		    htfs[htf], hts->sbit, hts->dept, hts->dmax, index);
	pr_ht_debug("-----------------------------------------------\n");
	bits = ht_bits_from_depth(hts->sbit, dept);
	key = ht_get_hkey(index, dept, bits, hts->idxt);
__next:
	ncnt = ht_ncnt_get(hcurr->next);

	pr_ht_debug("d:%d b:%u [%u] %p(%u): ", dept, bits, key, hcurr, ncnt);
	offset = 0;
	hlist_for_each_entry_safe(pos, tmp, &hcurr->head, hnode) {
		if (pos->index == index) {
			pr_ht_debug("%u:%llu(@) FOUND.", offset, pos->index);
		} else {
			pr_ht_debug("%u:%llu> ", offset, pos->index);
		}
		offset++;
	}
	pr_ht_debug("\n");

	hcurr = ht_ncnt_pointer(hcurr->next);
	if (hcurr) {
		dept++;
		bits = ht_bits_from_depth(hts->sbit, dept);
		key = ht_get_hkey(index, dept, bits, hts->idxt);
		hcurr = &hcurr[key];
		goto __next;
	}
}

/**
 * __htree_debug_walks_all - private call recursively to show all indexes
 * @hts: htree_state pointer
 * @htree: hash_tree root pointer
 * @index: index to find
 */
static void __htree_debug_walks_all(struct htree_state *hts,
				    struct hash_tree *htree, u64 index)
{
	u8 bits, ncnt;
	u16 k, anum, pnum;
	struct hash_tree *_next;
	struct htree_data *hdata;
	struct hlist_node *tmp;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	anum = HTREE_ARRAY_SIZE(bits);

	for (k = 0; k < anum; k++) {
		ncnt = ht_ncnt_get(htree[k].next);
		if (ncnt > 0) {
			bits = ht_bits_from_depth(hts->sbit, hts->dept);
			pr_ht_debug("d:%u b:%u [%u] %p (%u): ",
				    hts->dept, bits, k, &htree[k], ncnt);

			hlist_for_each_entry_safe(hdata, tmp, 
						  &htree[k].head, hnode) {
				if (hdata->index == index) {
					pr_ht_debug("< ((%llu)) ", hdata->index);
				} else {
					pr_ht_debug("< %llu ", hdata->index);
				}
			}
		}
		_next = ht_ncnt_pointer(htree[k].next);
		if (_next) {
			pr_ht_debug(">>\n");
			hts->dept++;
			pnum = anum;
			/* recursive call */
			__htree_debug_walks_all(hts, _next, index);
			anum = pnum;
			hts->dept--;
		} else {
			pr_ht_debug("\n%u]] ", k);
			continue;
		}
		pr_ht_debug(".\n\n");
	}
}

/**
 * htree_walks_all_debug - display to debug all indexes
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 * @index: index to find
 *
 * this function cycles through all hash tables and outputs all indexes.
 */
static void htree_debug_walks_all(struct htree_state *hts,
				  struct htree_root *root, u64 index)
{
	pr_ht_debug("[@@@@) walking: sbit:%u, dmax:%u, acnt:%d, dcnt:%llu\n\n",
		    hts->sbit, hts->dmax, hts->acnt, hts->dcnt);

	hts->dept = 0;
	__htree_debug_walks_all(hts, htree_first_rcu(root), index);

	pr_ht_debug("(@@@@] done: sbit:%u, dmax:%u, acnt:%d, dcnt:%llu\n\n",
		    hts->sbit, hts->dmax, hts->acnt, hts->dcnt);
}
#endif	/* HTREE_DEBUG_DETAIL */

/**
 * __htree_erase_all_lock - erase udata all
 * @hts: htree_state pointer
 * @htree: hash_tree root pointer
 * @erased: erased udata count
 *
 * this function cycles through all hash tables and erase udata all
 */
static void __htree_erase_all_lock(struct htree_state *hts,
			     struct hash_tree *htree, u64 *erased)
{
	u8 bits, ncnt;
	u16 k, anum, pnum;
	struct hash_tree *_next;
	struct htree_data *pos;
	struct hlist_node *tmp;
	struct data_struct *udata;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	anum = HTREE_ARRAY_SIZE(bits);

	for (k = 0; k < anum; k++) {
		ncnt = ht_ncnt_get(htree[k].next);
		if (ncnt > 0) {
			bits = ht_bits_from_depth(hts->sbit, hts->dept);
			hlist_for_each_entry_safe(pos, tmp,
						  &htree[k].head, hnode) {
				hlist_del(&pos->hnode);
				udata = hlist_entry_safe(pos, 
						struct data_struct, hdata);
				if (udata) {
					kfree(udata);
					(*erased)++;
				}
			}
		}
		_next = ht_ncnt_pointer(htree[k].next);
		if (_next) {
			hts->dept++;
			pnum = anum;
			/* recursive call */
			__htree_erase_all_lock(hts, _next, erased);
			anum = pnum;
			hts->dept--;
		} else {
			continue;
		}
	}
}

/**
 * htree_erase_all_lock -  erase udata all
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 *
 * return: erased all udata count
 */
static u64 htree_erase_all_lock(struct htree_state *hts, struct htree_root *root)
{
	u64 erased = 0;

	pr_ht_info("[~~~~) erase all: sbit:%u, dmax:%u, acnt:%d, dcnt:%llu\n",
		   hts->sbit, hts->dmax, hts->acnt, hts->dcnt);

	hts->dept = 0;

	ht_lock(root);
	__htree_erase_all_lock(hts, htree_first_rcu_locked(root), &erased);
	ht_unlock(root);

	pr_ht_info("(~~~~] done: sbit:%u, acnt:%d, dcnt:%llu, erased:%llu\n\n",
		   hts->sbit, hts->acnt, hts->dcnt, erased);

	return erased;
}

/**
 * _htree_insert_range - insert udata to hash tree using ht_insert()
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 * @start: start index to insert
 * @end: end index to insert
 * @gap: gap between indices
 * @req: request flags
 *
 * If there is the same index:
 * if req is htf_ins, the new udata is inserted next to each other.
 * if req is htf_erase, the new udata is inserted, and old udata is erased.
 */
static u64 _htree_insert_range(struct htree_state *hts, struct htree_root *root,
			       u64 start, u64 end, u64 gap, enum ht_flags req)
{
	u64 index;
	u64 loop = 0, ins = 0, era = 0;
	struct data_struct *udata;
	struct htree_data *rdata;

	pr_ht_info("[++++) inserting: [s:%llu ... e:%llu] (g:%llu)\n",
		   start, end, gap);
	for (index = start; index <= end; index += gap) {
		udata = _htree_data_alloc(index);
		rdata = ht_insert_lock(hts, root, &udata->hdata, req);
		if (req == htf_erase && rdata) {
			udata = hlist_entry_safe(rdata, struct data_struct, hdata);
			if (udata && rdata->index == index) {
				kfree(udata);
				era++;
			}
		}
		ins++;
		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}
	pr_ht_info("(++++] done: loop:%llu, inserted:%llu, same erased:%llu\n\n",
		   loop, ins, era);

	return ins - era;
}

/**
 * _htree_find_range - find udata in the hash tree using ht_find()
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 * @start: start index to find
 * @end: end index to find
 * @gap: gap between indices
 */
static u64 _htree_find_range(struct htree_state *hts, struct htree_root *root,
			     u64 start, u64 end, u64 gap)
{
	u64 index;
	u64 loop = 0, found = 0;
	struct data_struct *udata;
	struct htree_data *rdata;

	pr_ht_info("[****) finding: [s:%llu ... e:%llu] (g:%llu)\n",
		   start, end, gap);
	for (index = start; index <= end; index += gap) {
		rdata = ht_find(hts, htree_first_rcu(root), index);
		if (rdata) {
			udata = hlist_entry_safe(rdata, struct data_struct, hdata);
			if (udata && rdata->index == index) {
				pr_ht_find("*todo: find:<%llu> %c %c %c\n",
				index, udata->a, (char)udata->b, (char)udata->c);
				found++;
			}
		}

		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}
	pr_ht_info("(****] done: loop:%llu, found:%llu, diff:%llu\n\n",
		   loop, found, loop - found);
	return found;
}

/**
 * _htree_erase_range - erase udata from hash tree using ht_erase()
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 * @start: start index to erase
 * @end: end index to erase
 * @gap: gap between indices
 */
static u64 _htree_erase_range(struct htree_state *hts, struct htree_root *root,
			      u64 start, u64 end, u64 gap)
{
	u64 index;
	u64 loop = 0, erased = 0;
	struct hash_tree *htree;
	struct data_struct *udata;
	struct htree_data *rdata;

	pr_ht_info("[----) erasing: [s:%llu ... e:%llu] (g:%llu)\n",
		   start, end, gap);
	for (index = start; index <= end; index += gap) {
		htree = htree_first_rcu(root);
		rdata = ht_erase_lock(hts, root, index);
		if (rdata) {
			udata = hlist_entry_safe(rdata, struct data_struct, hdata);
			if (udata && rdata->index == index) {
				pr_ht_erase("*todo: erase:<%llu> %c %c %c\n",
				index, udata->a, (char)udata->b, (char)udata->c);
				kfree(udata);
				erased++;
			}
#ifdef HTREE_DEBUG_DETAIL
		} else {
			hts->hkey = ht_get_hkey(index, 0, hts->sbit, hts->idxt);
			htree_debug_hdata(hts, &htree[hts->hkey], index, htf_erase);
#endif
		}
		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}
	pr_ht_info("(----] done: loop:%llu, erased:%llu, diff:%llu\n\n",
		   loop, erased, loop - erased);
	return erased;
}

/**
 * _htree_update_range - update udata in the hash tree using ft_find()
 * @hts: htree_state pointer
 * @root: hash_tree root pointer
 * @start: start index to update
 * @end: end index to update
 * @gap: gap between indices
 */
static u64 _htree_update_range(struct htree_state *hts, struct htree_root *root,
			u64 start, u64 end, u64 gap)
{
	u64 index;
	u64 loop = 0, updated = 0;
	struct hash_tree *htree;
	struct data_struct *udata;
	struct htree_data *rdata;

	pr_ht_info("[####) updating: [s:%llu ... e:%llu] (g:%llu)\n",
		   start, end, gap);
	for (index = start; index <= end; index += gap) {
		htree = htree_first_rcu(root);
		rdata = ht_find(hts, htree, index);
		if (rdata) {
			udata = hlist_entry_safe(rdata, struct data_struct, hdata);
			if (udata && rdata->index == index) {
				pr_ht_update("*todo: update:<%llu> %c %c %c ",
				index, udata->a, (char)udata->b, (char)udata->c);
				/* todo: update user defined data */
				udata->a -= 32;
				udata->b -= 32;
				udata->c -= 32;

				pr_ht_update(">> %c %c %c\n",
					udata->a, (char)udata->b, (char)udata->c);
				updated++;
			}
#ifdef HTREE_DEBUG_DETAIL
		} else {
			hts->hkey = ht_get_hkey(index, 0, hts->sbit, hts->idxt);
			htree_debug_hdata(hts, &htree[hts->hkey], index, htf_update);
#endif
		}
		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}
	pr_ht_info("(####] done: loop:%llu, updated:%llu, diff:%llu\n\n",
		   loop, updated, loop - updated);

	return updated;
}

/**
 * _htree_statis - calculate hash tree statistics and get into hts.
 * @hts: htree_state pointer to store statistics
 * @root: hash_tree root pointer
 */
static void _htree_statis(struct htree_state *hts, struct htree_root *root)
{
	s32 acnt = 0;
	u64 dcnt = 0;

	ht_statis(hts, htree_first_rcu(root), &acnt, &dcnt);

	if (hts->dcnt == dcnt && hts->acnt == acnt) {
		pr_ht_info("[ OK ] statist: acnt:%d, dcnt:%llu ", acnt, dcnt);
	} else {
		pr_ht_info("[FAIL] statist: acnt:%d(%d), dcnt:%llu(%llu)\n",
			  acnt, hts->acnt, dcnt, hts->dcnt);
	}
	pr_ht_info(">> asum:%llu, eff:%llu(/100)\n\n",
		   hts->asum, HTREE_EFFICIENCY(hts->dcnt, hts->asum));
}

/**
 * _htree_statis_info - shows information calculated by htree_statis().
 * @hts: htree_state pointer to read statistics
 * @root: hash_tree root pointer
 */
static void _htree_statis_info(struct htree_state *hts, struct htree_root *root)
{
	u32 sizh = sizeof(struct hash_tree);
	u32 sizd = sizeof(struct data_struct);

	/* total data slot of full hash table area */
	u64 hsum = (sizh * hts->acnt) >> 10;
	u64 dsum = (sizd * hts->dcnt) >> 10;
	u64 smem = hsum + dsum;

	if (hts->asum == 0)
		_htree_statis(hts, root);

	pr_ht_stat("------------------------------------------\n");
	pr_ht_stat(" hash start bits(sbit) :       %10d\n", hts->sbit);
	pr_ht_stat(" hash tree max depth   :       %10u\n", hts->dmax);
	pr_ht_stat(" finding walks(wcnt)   :       %10u\n", hts->wcnt);
	pr_ht_stat(" user data alloc(dcnt) : %16llu\n",     hts->dcnt);
	pr_ht_stat(" hash tree alloc(acnt) :       %10d\n", hts->acnt);
	pr_ht_stat(" hash tree sum(asum)   : %16llu\n",     hts->asum);
	pr_ht_stat(" htree nodes sum(stot) : %16llu\n",
						HTREE_EFF_ASUM(hts->asum));
	pr_ht_info(" hlist node cnt(ncnt)  :       %10d\n", HTREE_NODE_CNT);
	pr_ht_info(" sizeof hash_tree(B)   :       %10u\n", sizh);
	pr_ht_info(" sizeof data_struct(B) :       %10u\n", sizd);
	pr_ht_info(" hash using mem(KB)    : %16llu\n",     hsum);
	pr_ht_info(" data using mem(KB)    : %16llu\n",	    dsum);
	pr_ht_stat(" total using mem(KB)   : %16llu\n",     smem);
	pr_ht_stat("------------------------------------------\n");
	pr_ht_stat(" efficiency(dcnt/stot) :   %8llu(/100)\n",
				HTREE_EFFICIENCY(hts->dcnt, hts->asum));
	pr_ht_stat("------------------------------------------\n\n");
}

/**
 * _htree_get_most_index - get most smallest and largest index
 *
 * if sort flag is HTREE_FLAG_ASCD, root hash table has the smallest index.
 * if sort flag is HTREE_FLAG_DECD, root hash table has the largest index.
 */
static void _htree_get_most_index(struct htree_state *hts, struct htree_root *root)
{
	struct htree_data *hdata;

	hdata = ht_most_index(hts, htree_first_rcu(root));
	if (hdata) {
		if (hts->sort == HTREE_FLAG_ASCD) {
			pr_ht_stat("[MOST] smallest index:%llu\n\n", hdata->index);
		} else {
			pr_ht_stat("[MOST] largest index:%llu\n\n", hdata->index);
		}
	}
}

/**
 * _htree_remove_all - remove all udata and hash trees
 *
 * before run ht_destroy_lock(), the udata must be erased all.
 * ht_destroy_lock() removes all hash trees, but it does not remove the udata.
 */
static void _htree_remove_all(struct htree_state *hts, struct htree_root *root)
{
	/* remove all udata */
	hts->dcnt -= htree_erase_all_lock(hts, root);
	if (hts->dcnt != 0) {
		pr_ht_warn("[WARN] erase remained acnt:%d, dcnt:%llu\n\n",
			   hts->acnt, hts->dcnt);
	}

	/* remove all hash trees */
	if (ht_destroy_lock(hts, root) == htf_ok) {
		pr_ht_stat("[ OK ] destroy remained acnt:%d, dcnt:%llu\n\n",
			   hts->acnt, hts->dcnt);
	} else {
		pr_ht_warn("[WARN] destroy remained acnt:%d, dcnt:%llu\n\n",
			   hts->acnt, hts->dcnt);
	}
}

/**
 * _htree_test_index_loop - main test loop
 * @hts: htree_state pointer
 * @start: starting index to test
 * @end: ending index to test
 *
 * return: dcnt: index(data) working count
 *
 * testing flow:
 *      insert --> erase,find --> insert,update --> statistic --> free,destroy
 */
static u64 _htree_test_index_loop(struct htree_state *hts, u64 start, u64 end)
{
	u64 inserted, found, erased, updated;
	u64 dcnt, slice;

	if (start > end)
		return 0;
	slice = (end - start) / 10 + 2;

	/* first root hash tree alloc */
	htree_root_alloc(hts, &ht_root);

	inserted = _htree_insert_range(hts, &ht_root, start, end, 1, htf_ins);
	if (inserted != hts->dcnt) {
		pr_ht_err("[FAIL] inserted:%llu, dcnt:%llu, diff:%lld\n\n",
			  inserted, hts->dcnt, inserted - hts->dcnt);
	}

	_htree_statis(hts, &ht_root);

	erased = _htree_erase_range(hts, &ht_root, start, end, slice);
	found = _htree_find_range(hts, &ht_root, start, end, slice);
	if (found) {
		pr_ht_err("[FAIL] erased:%llu, found:%llu, diff:%lld\n\n",
			  erased, found, erased - found);
	}

	_htree_statis(hts, &ht_root);

	inserted = _htree_insert_range(hts, &ht_root, start, end, slice, htf_ins);
	updated = _htree_update_range(hts, &ht_root, start, end, slice);
	if (inserted != updated) {
		pr_ht_err("[FAIL] inserted:%llu, updated:%llu, diff:%lld\n\n",
			  inserted, updated, inserted - updated);
	}

	_htree_statis(hts, &ht_root);
	_htree_get_most_index(hts, &ht_root);

#ifdef HTREE_DEBUG_DETAIL
	htree_debug_walks_all(hts, &ht_root, 0);
#endif
	_htree_statis_info(hts, &ht_root);
	dcnt = hts->dcnt;

	_htree_remove_all(hts, &ht_root);

	return dcnt;
}

/**
 * _htree_test_idx_range - index test of 32bits/64bits, ascending/descending
 * @idx_type: hts->idxt: index type [0:64bits, 1:32bits]
 * @sort_type: hts->sort: sorting type [0:ascending, 1:descending]
 *
 * Importance: must be use the ht_hts_clear_init() to adjust htree depth.
 *
 * hash array size(anum): 1 << (sbit - depth)
 * dnum: [d0:anum x d1:anum x d2:anum x d3:anum x d4:anum x d5:anum ...)
 *
 * number of index(nr) is between 32M and 64M, and hash tree depth is [2,3)
 *
 * htree depth avg(d): (3)
 * hlist node cnt(c) : [4)
 * efficiency O(n)   : (d) x c == 3 x 4 == 12 (finding walks)
 * using memory eff  : (dcnt / asum) == 85%(/100 == 0.85)
 *
 * you can test by changing start, end with 32bits or 64bits data type.
 * Be careful:  if system has 4GB memory:
 * 		if (index nr > 128M) then depth > 3, out of memory(OOM)
 */
static void _htree_test_idx_range(u8 idx_type, u8 sort_type)
{
	u64 start, end, maxnr;
	u64 idx, dcnt, eff = 0;
	u32 wcnt = 0;
	const u8 loopnr = 14;
	const u32 v1k = 1 << 10;
	const u64 v1t = (u64)1 << 40;
	const char *idxts[] = {	"64bits", "32bits" };
	const char *sorts[] = {	"ASCD", "DECD" };

	struct htree_state *hts = ht_hts_alloc();

	for (idx = 1; idx <= loopnr; idx++) {
		pr_ht_stat("[START) RANGE(insert, erase, find, update) \
index type:<%s>, sorting type:<%s>\n", idxts[idx_type], sorts[sort_type]);

		start = (idx_type == HTREE_FLAG_IDX32) ? idx * v1k : idx * v1t;
		end = start + (1 << idx) * v1k;
		maxnr = end - start + 1;

		/* setting hash tree depth, index type and sorting type */
		ht_hts_clear_init(hts, maxnr, idx_type, sort_type);

		pr_ht_stat(
		"[loop) %llu: sbit:%u, start:%llu, end:%llu, maxnr:%llu\n\n",
					idx, hts->sbit, start, end, maxnr);

		dcnt = _htree_test_index_loop(hts, start, end);
		eff += HTREE_EFFICIENCY(dcnt, hts->asum);
		wcnt += hts->wcnt;
	}
	/*
	 * loopnr:14(16M) 32bits: ascending  efficiency avg: 85/100, wcnt: 9
	 * loopnr:14(16M) 32bits: descending efficiency avg: 85/100, wcnt: 8
	 *
	 * loopnr:14(16M) 64bits: ascending  efficiency avg: 97/100, wcnt:10
	 * loopnr:14(16M) 64bits: descending efficiency avg: 97/100, wcnt: 7
	 */
	pr_ht_stat("=======================================================\n");
	pr_ht_stat("( END] RANGE index type:<%s>, sorting type:<%s>\n",
		   idxts[idx_type], sorts[sort_type]);
	pr_ht_stat("( EFF] loop:%u, efficiency avg:%llu(/100), wcnt:(%u)\n\n",
		   loopnr, eff / loopnr, wcnt / loopnr);
	kfree(hts);
}

/**
 * _htree_test_idx_random - random index test
 * @idx_type: hts->idxt: index type [0:64bits, 1:32bits]
 * @sort_type: hts->sort: sorting type [0:ascending, 1:descending]
 * @maxnr: max number of index
 *
 * testing flow:
 * 	random index --> ht_insert() --> ht_erase() --> statis info --> free all
 */
static void _htree_test_idx_random(u8 idx_type, u8 sort_type, u64 maxnr)
{
	u64 i, index;
	struct data_struct *udata;
	struct htree_data *rdata;
	u64 loop = 0, inserted = 0, erased = 0;
	const char *idxts[] = {	"64bits", "32bits" };
	const char *sorts[] = {	"ASCD", "DECD" };
	const u64 check_idx = 25203307;

	struct htree_state *hts = ht_hts_alloc();

	/* setting hash tree depth, index type and sorting type */
	ht_hts_clear_init(hts, maxnr, idx_type, sort_type);

	/* first root hash tree alloc */
	htree_root_alloc(hts, &ht_root);

	pr_ht_stat("[START) RANDOM: sbit:%u, index type:<%s>, sorting type:<%s>\n\n",
		   hts->sbit, idxts[idx_type], sorts[sort_type]);

	udata = _htree_data_alloc(check_idx);
	rdata = ht_insert_lock(hts, &ht_root, &udata->hdata, htf_ins);
	inserted++;
	loop++;

	pr_ht_stat("[loop) %llu: random insert\n\n", maxnr);
	for (i = 0; i < maxnr; i++) {
		index = (idx_type == HTREE_FLAG_IDX32) ? 
			get_random_u32() : get_random_u64();

		udata = _htree_data_alloc(index);
		rdata = ht_insert_lock(hts, &ht_root, &udata->hdata, htf_ins);
		if (!rdata)
			inserted++;
		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}

	_htree_statis(hts, &ht_root);

	rdata = ht_find(hts, htree_first_rcu(&ht_root), check_idx);
	if (!rdata) {
		pr_ht_err("[FAIL] NOT found check index:%llu\n\n", check_idx);
	}

	maxnr *= 2;
	pr_ht_stat("[loop) %llu: random erase\n\n", maxnr);
	for (i = 0; i < maxnr; i++) {
		index = (idx_type == HTREE_FLAG_IDX32) ? 
			get_random_u32() : get_random_u64();

		rdata = ht_erase_lock(hts, &ht_root, index);
		if (rdata) {
			udata = hlist_entry_safe(rdata, struct data_struct, hdata);
			if (udata && rdata->index == index) {
				pr_ht_erase("*todo: erase:<%llu> %c %c %c\n",
				index, udata->a, (char)udata->b, (char)udata->c);
				kfree(udata);
				erased++;
			}
		}
		loop++;
		if (!(loop % HTREE_TEST_SCHED_CNT))
			schedule();
	}

	_htree_statis(hts, &ht_root);

	rdata = ht_find(hts, htree_first_rcu(&ht_root), check_idx);
	if (!rdata) {
		pr_ht_info("[INFO] check index:%llu (erased)\n\n", check_idx);
	}

	pr_ht_stat("( END] RANDOM loop:%llu, inserted:%llu, erased:%llu\n\n",
		   loop, inserted, erased);

#ifdef HTREE_DEBUG_DETAIL
	htree_debug_walks_all(hts, &ht_root, 0);
#endif

	_htree_get_most_index(hts, &ht_root);
	_htree_statis_info(hts, &ht_root);

	_htree_remove_all(hts, &ht_root);

	kfree(hts);
}

/**
 * _htree_test_index_same - same index test
 * @idx_type: hts->idxt: index type [0:64bits, 1:32bits]
 * @sort_type: hts->sort: sorting type [0:ascending, 1:descending]
 * @maxnr: max number of index
 *
 * If there is the same index:
 * if req is htf_ins, the new udata is inserted next to each other.
 * if req is htf_erase, the new udata is inserted, and old udata is erased.
 *
 * testing flow:
 * 	new index --> ht_insert() --> same index --> ht_insert() --> statis info
 */
static void _htree_test_index_same(u8 idx_type, u8 sort_type, u64 maxnr)
{
	u64 inserted, found;
	const char *idxts[] = {	"64bits", "32bits" };
	const char *sorts[] = {	"ASCD", "DECD" };
	const u32 gap = 2;

	struct htree_state *hts = ht_hts_alloc();

	/* setting hash tree depth, index type and sorting type */
	ht_hts_clear_init(hts, maxnr, idx_type, sort_type);

	/* first root hash tree alloc */
	htree_root_alloc(hts, &ht_root);

	pr_ht_stat("[START) SAME: sbit:%u, index type:<%s>, sorting type:<%s>\n\n",
		   hts->sbit, idxts[idx_type], sorts[sort_type]);

	pr_ht_stat("[loop) %llu: new index inserting(htf_ins)\n\n", maxnr);
	inserted = _htree_insert_range(hts, &ht_root, 0, maxnr, gap - 1, htf_ins);
	if (inserted != hts->dcnt) {
		pr_ht_err("[FAIL] inserted:%llu, dcnt:%llu, diff:%lld\n\n",
			  inserted, hts->dcnt, inserted - hts->dcnt);
	}

	_htree_statis(hts, &ht_root);

	pr_ht_stat("[loop) %llu: SAME index inserting(htf_erase)\n\n", maxnr);
	inserted = _htree_insert_range(hts, &ht_root, 1, maxnr, gap, htf_erase);
	if (inserted != 0) {
		pr_ht_err("[FAIL] inserted:%llu, dcnt:%llu, diff:%lld\n\n",
			  inserted, hts->dcnt, inserted - hts->dcnt);
	}

	pr_ht_stat("[loop) %llu: SAME index inserting(htf_ins)\n\n", maxnr);
	inserted = _htree_insert_range(hts, &ht_root, 1, maxnr, gap, htf_ins);
	if (inserted != (maxnr / gap)) {
		pr_ht_err("[FAIL] inserted:%llu, dcnt:%llu, diff:%lld\n\n",
			  inserted, hts->dcnt, inserted - hts->dcnt);
	}

	found = _htree_find_range(hts, &ht_root, 0, maxnr, gap - 1);
	if (found != (hts->dcnt - inserted)) {
		pr_ht_err("[FAIL] dcnt:%llu, inserted:%llu, found:%llu\n\n",
			  hts->dcnt, inserted, found);
	}

	_htree_statis(hts, &ht_root);

#ifdef HTREE_DEBUG_DETAIL
	htree_debug_walks_all(hts, &ht_root, 0);
#endif
	_htree_get_most_index(hts, &ht_root);
	_htree_statis_info(hts, &ht_root);

	_htree_remove_all(hts, &ht_root);

	kfree(hts);
}

#ifdef HTREE_DEBUG_DETAIL
/**
 * _htree_test_index_debug - simple index test on debug mode
 *
 * show detailed hash tree information
 */
static void htree_debug_index(void)
{
	struct htree_state *hts = ht_hts_alloc();

	ht_hts_clear_init(hts, 32, HTREE_FLAG_IDX64, HTREE_FLAG_DECD);
	_htree_test_index_loop(hts, 0,  32);

	ht_hts_clear_init(hts, 32, HTREE_FLAG_IDX32, HTREE_FLAG_ASCD);
	_htree_test_index_loop(hts, 0, 32);

	_htree_test_idx_random(HTREE_FLAG_IDX64, HTREE_FLAG_ASCD, 32);
	_htree_test_idx_random(HTREE_FLAG_IDX32, HTREE_FLAG_DECD, 32);

	_htree_test_index_same(HTREE_FLAG_IDX64, HTREE_FLAG_ASCD, 32);
	_htree_test_index_same(HTREE_FLAG_IDX32, HTREE_FLAG_DECD, 32);

	kfree(hts);
}
#endif

static int __init htree_test_init(void)
{
	const u64 v1m = 1 << 20;

	_htree_test_hash();

#ifdef HTREE_DEBUG_DETAIL
	htree_debug_index();
	return 0;
#endif

	/* range(insert, erase, find, update) index testing */
	_htree_test_idx_range(HTREE_FLAG_IDX64, HTREE_FLAG_ASCD);
	_htree_test_idx_range(HTREE_FLAG_IDX64, HTREE_FLAG_DECD);

	_htree_test_idx_range(HTREE_FLAG_IDX32, HTREE_FLAG_ASCD);
	_htree_test_idx_range(HTREE_FLAG_IDX32, HTREE_FLAG_DECD);

	/* random index testing */
	_htree_test_idx_random(HTREE_FLAG_IDX64, HTREE_FLAG_DECD, v1m);
	_htree_test_idx_random(HTREE_FLAG_IDX32, HTREE_FLAG_ASCD, v1m);

	/* same index testing */
	_htree_test_index_same(HTREE_FLAG_IDX64, HTREE_FLAG_ASCD, v1m);
	_htree_test_index_same(HTREE_FLAG_IDX32, HTREE_FLAG_DECD, v1m);

	return 0;
}

static void __exit htree_test_exit(void)
{
	pr_info("htree test exit.\n");
}

module_init(htree_test_init)
module_exit(htree_test_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JaeJoon Jung <rgbi3307@gmail.com>");
MODULE_DESCRIPTION("Hash Tree Test");

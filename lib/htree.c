// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Hash-Trees implementation
 *  lib/htree.c
 *
 *  Copyright(C) 2024, JaeJoon Jung <rgbi3307@gmail.com>
 */

#include <linux/htree.h>

/**
 * ht_table_alloc - memory allocation of hash table
 * @hts: hts->acnt increase
 * return: htree: allocated memory pointer
 *
 * hash bits is calculated using the ht_bits_from_depth()
 *      that is important to decision the depth of hash tree.
 * hts->sbit is determined in the _ht_hts_get_sbit() function
 *      in proportion to the total number of indexes.
 * hash array(table) size is (1 << bits).
 */
struct hash_tree *ht_table_alloc(struct htree_state *hts)
{
	u8 bits;
	u16 k, anum;
	struct hash_tree *htree;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	anum = HTREE_ARRAY_SIZE(bits);
	htree = (struct hash_tree *)
		kmalloc_array(anum, sizeof(struct hash_tree), GFP_KERNEL);

	for (k = 0; k < anum; k++) {
		INIT_HLIST_HEAD(&htree[k].head);
		htree[k].next = NULL;
	}
	hts->acnt++;

	return htree;
}
EXPORT_SYMBOL(ht_table_alloc);

/**
 * ht_hts_alloc - memory allocation of htree_state struct
 * return: hts: allocated memory pointer
 *
 * htree_state is the numeric data structure for operations.
 * It is used to calculate the starting bit and depth of the hash tree,
 *      number of searches, number of memory allocations, and usage efficiency.
 */
struct htree_state *ht_hts_alloc(void)
{
	struct htree_state *hts = (struct htree_state *)
			kmalloc(sizeof(struct htree_state), GFP_KERNEL);
	return hts;
}
EXPORT_SYMBOL(ht_hts_alloc);

/**
 * _ht_hts_get_sbit - starting bit to determine hash table size
 * @maxnr: maximum number of indexes to use in the system
 * return: starting bit(stored in hts->sbit)

 * Determine the size of the hash table by choosing the starting number of
 * bits for the hash tree.  Increase memory usage efficiency by optimizing
 * hash table size in proportion to index quantity(maxnr).
 * hts->sbit enables maintain memory usage efficiency more than 80%.
 */
static u8 _ht_hts_get_sbit(u64 maxnr)
{
	u8 sbit = 0;
	do {
		maxnr >>= HTREE_BITS_SHIFT;
		sbit++;
	} while(maxnr > 0);

	return (sbit < HTREE_BITS_END) ? HTREE_BITS_END : sbit;
}

/**
 * ht_hts_clear_init - clear & init of htree statistic structure
 * @hts: htree_state struct pointer
 * @maxnr: maximum number of indexes to use in the system
 * @idxt: type of index [0:64bits, 1:32bits]
 * @sort: index sorting type [0:ascending, 1:descending]
 *
 * hts->sbit is determined in the _ht_hts_get_sbit() function
 *      in proportion to the total number of indexes(maxnr).
 */
void ht_hts_clear_init(struct htree_state *hts, u64 maxnr, u8 idxt, u8 sort)
{
	memset(hts, 0, sizeof(struct htree_state));

	hts->sbit = _ht_hts_get_sbit(maxnr);
	hts->idxt = idxt;
	hts->sort = sort;
}
EXPORT_SYMBOL(ht_hts_clear_init);

/**
 * __ht_find - private function to call recursively to find index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @index: user index to find
 * @rdata: node data at the searched location to return
 * @rtree: hash tree at the searched location to return
 */
static enum ht_flags __ht_find(struct htree_state *hts, struct hash_tree *htree,
		u64 index, struct htree_data **rdata, struct hash_tree **rtree)
{
	struct htree_data *pos;
	u8 bits, ncnt;

_retry:
	*rtree = htree;
	ncnt = ht_ncnt_get(htree[hts->hkey].next);
	if (ncnt == 0)
		goto _next_step;

	hlist_for_each_entry(pos, &htree[hts->hkey].head, hnode) {
		*rdata = pos;
		hts->wcnt++;
		if (pos->index > index) {
			if (hts->sort == HTREE_FLAG_ASCD)
				return htf_find_gt;

		} else if (pos->index < index) {
			if (hts->sort == HTREE_FLAG_DECD)
				return htf_find_lt;

		} else {
			return htf_find;
		}
	}

_next_step:
	htree = ht_ncnt_pointer(htree[hts->hkey].next);
	if (htree) {
		hts->dept++;
		bits = ht_bits_from_depth(hts->sbit, hts->dept);
		hts->hkey = ht_get_hkey(index, hts->dept, bits, hts->idxt);
		goto _retry;
	}
	return htf_none;
}

/**
 * ht_find - private function to find index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @index: user index to find
 * @rdata: node data at the searched location to return(**)
 * @rtree: hash tree at the searched location to return(**)
 */
static enum ht_flags _ht_find(struct htree_state *hts, struct hash_tree *htree,
	      u64 index, struct htree_data **rdata, struct hash_tree **rtree)
{
	enum ht_flags ret;

	hts->wcnt = 0;
	hts->dept = 0;
	hts->hkey = ht_get_hkey(index, 0, hts->sbit, hts->idxt);

	ret = __ht_find(hts, htree, index, rdata, rtree);

	return ret;
}

/**
 * ht_find - public function to find index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @index: user index to find
 *
 * return: rdata: found node data to return
 */
struct htree_data *ht_find(struct htree_state *hts,
			   struct hash_tree *htree, u64 index)
{
	struct htree_data *rdata = NULL;
	struct hash_tree *rtree;

	if (!htree)
		return NULL;

	if (_ht_find(hts, htree, index, &rdata, &rtree) == htf_find)
		return rdata;
	return NULL;
}
EXPORT_SYMBOL(ht_find);

/**
 * _ht_move_to_next - private function to call recursively to move index
 * @hts: htree_state pointer
 * @sdata: hash list node
 * @prev: previous hash_tree pointer
 * @ntree: next hash_tree
 *
 * The number of lists linking to the same hash key is HTREE_MAX_NCNT.
 * If this is exceeded, it moves to the next hash table in sequence.
 */
static void _ht_move_to_next(struct htree_state *hts, struct htree_data *sdata,
			     struct hash_tree *prev, struct hash_tree *ntree)
{
	u8 bits, ncnt, dept = hts->dept;
	u16 hkey;
	struct htree_data *edata;
	struct htree_data *pos, *rdata = NULL;
	enum ht_flags htf;

_retry:
	edata = sdata;
	pos = sdata;
	/* find the end node on the current(prev) */
	hlist_for_each_entry_from(pos, hnode)
		edata = pos;

	hlist_del(&edata->hnode);
	INIT_HLIST_NODE(&edata->hnode);
	WRITE_ONCE(prev->next, ht_ncnt_dec(prev->next, 1));

	dept++;
	bits = ht_bits_from_depth(hts->sbit, dept);
	hkey = ht_get_hkey(edata->index, dept, bits, hts->idxt);

	if (!ntree) {
		ncnt = ht_ncnt_get(prev->next);
		ntree = ht_table_alloc(hts);
		WRITE_ONCE(prev->next, ht_ncnt_set(ntree, ncnt));
		htree_add_head(ntree, &edata->hnode, hkey);
		goto _next;
	}

	ncnt = ht_ncnt_get(ntree[hkey].next);
	if (ncnt == 0) {
		htree_add_head(ntree, &edata->hnode, hkey);
		goto _next;
	}

	htf = htf_none;
	hlist_for_each_entry(pos, &ntree[hkey].head, hnode) {
		rdata = pos;
		if (hts->sort == HTREE_FLAG_ASCD &&
				pos->index >= edata->index) {
			htf = htf_find_gt;
			hlist_add_before(&edata->hnode, &rdata->hnode);
			break;
		}
		if (hts->sort == HTREE_FLAG_DECD &&
				pos->index <= edata->index) {
			htf = htf_find_lt;
			hlist_add_before(&edata->hnode, &rdata->hnode);
			break;
		}
	}
	if (htf < htf_find_lt)
		hlist_add_behind(&edata->hnode, &rdata->hnode);

_next:
	WRITE_ONCE(ntree[hkey].next, ht_ncnt_inc(ntree[hkey].next, 1));

	ncnt = ht_ncnt_get(ntree[hkey].next);
	if (ncnt > HTREE_MAX_NCNT(dept)) {
		sdata = edata;
		prev = &ntree[hkey];
		ntree = ht_ncnt_pointer(ntree[hkey].next);
		goto _retry;
	}
}

/**
 * ht_insert - insert the user index into the hash tree.
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @index: user index to insert
 * @rdata: destination data pointer of hlist node
 * @hdata: source data pointer of hlist node
 * @htf: working flags
 *
 * The flow linked to a specific depth of the hash tree by a hash key:
 *      user index --> hash key --> hash tree --> depth --> hash lists
 */
static void _ht_insert(struct htree_state *hts, struct hash_tree *htree,
		       struct htree_data *rdata, struct htree_data *hdata,
		       enum ht_flags htf, enum ht_flags req)
{
	struct htree_data *edata = hdata;
	u64 index = hdata->index;
	u8 bits, ncnt;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	hts->hkey = ht_get_hkey(index, hts->dept, bits, hts->idxt);
	ncnt = ht_ncnt_get(htree[hts->hkey].next);

	if (ncnt == 0) {
		htree_add_head(htree, &hdata->hnode, hts->hkey);
		goto _finish;
	}

	/*
	 * if (hts->sort == HTREE_FLAG_ASCD) then htf is htf_find_gt
	 * if (hts->sort == HTREE_FLAG_DECD) then htf is htf_find_lt
	 */
	if (htf == htf_find_gt || htf == htf_find_lt) {
		hlist_add_before(&hdata->hnode, &rdata->hnode);
		edata = rdata;
		if (hts->dept == 0 && hts->wcnt == 1)
			hts->most = hts->hkey;
	} else {
		hlist_add_behind(&hdata->hnode, &rdata->hnode);
		edata = hdata;
	}

_finish:
	if (req == htf_ins) {
		WRITE_ONCE(htree[hts->hkey].next, 
				ht_ncnt_inc(htree[hts->hkey].next, 1));
		hts->dcnt++;
		ncnt++;
	}

	if (ncnt > HTREE_MAX_NCNT(hts->dept)) {
		_ht_move_to_next(hts, edata, &htree[hts->hkey],
				ht_ncnt_pointer(htree[hts->hkey].next));
	}
}

/**
 * ht_insert - public function to insert udata
 * @hts: htree_state pointer
 * @htree: hash_tree root pointer
 * @udata: data_struct to insert
 * @req: flag to proceed further after index insertion
 *
 * return: rdata: searched node data to return
 *
 * If there is the same index:
 * if req is htf_ins, the new udata is inserted next to each other.
 * if req is htf_erase, the new udata is inserted, and old udata is erased.
 *
 * insert flow:
 *      _ht_find() --> finding rdata, rtree --> _ht_insert()
 */
struct htree_data *ht_insert(struct htree_state *hts, struct hash_tree *htree,
			     struct htree_data *hdata, enum ht_flags req)
{
	struct htree_data *rdata = NULL;
	struct hash_tree *rtree = NULL;
	enum ht_flags htf;

	if (!htree)
		return NULL;

	htf = _ht_find(hts, htree, hdata->index, &rdata, &rtree);

	_ht_insert(hts, rtree, rdata, hdata, htf, req);

	if (htf == htf_find && req == htf_erase) {
		hlist_del(&rdata->hnode);
		return rdata;
	}
	return NULL;
}
EXPORT_SYMBOL(ht_insert);

/**
 * ___ht_erase - delete an empty hash tree
 * @hts: htree_state pointer
 * @htree: hash_tree to check if empty
 * @bits: bits of this hash tree
 */
static enum ht_flags ___ht_erase(struct htree_state *hts,
				 struct hash_tree *htree, u8 bits)
{
	u16 k;
	u16 anum = HTREE_ARRAY_SIZE(bits);

	for (k = 0; k < anum; k++)
		if (htree[k].next)
			break;

	if (k == anum) {
		kfree(htree);
		hts->acnt--;
		hts->dept--;
		return htf_freed;
	}
	return htf_erase;
}

/**
 * __ht_erase - private function to call recursively to erase index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @rdata: searched node data to erase
 * @index: user index to erase
 */
static int __ht_erase(struct htree_state *hts, struct hash_tree *htree,
		      struct htree_data **rdata, u64 index)
{
	struct hash_tree *_next;
	struct htree_data *pos;
	struct hlist_node *tmp;
	enum ht_flags ret = htf_none;
	u8 bits, ncnt;
	u16 key = hts->hkey;

	ncnt = ht_ncnt_get(htree[key].next);
	bits = ht_bits_from_depth(hts->sbit, hts->dept);

	if (ncnt == 0)
		goto _next_step;

	hlist_for_each_entry_safe(pos, tmp, &htree[key].head, hnode) {
		if (pos->index == index) {
			hlist_del(&pos->hnode);
			ncnt--;
			hts->dcnt--;
			WRITE_ONCE(htree[key].next, 
					ht_ncnt_set(htree[key].next, ncnt));
			*rdata = pos;
			ret = htf_erase;
			break;
		} else {
			if (hts->sort == HTREE_FLAG_ASCD && pos->index > index)
				break;
			if (hts->sort == HTREE_FLAG_DECD && pos->index < index)
				break;
		}
	}

	if (ncnt == 0)
		ret = ___ht_erase(hts, htree, bits);

	if (ret > htf_none)	/* erased or freed */
		return ret;
_next_step:
	_next = ht_ncnt_pointer(htree[key].next);
	if (_next) {
		hts->dept++;
		bits = ht_bits_from_depth(hts->sbit, hts->dept);
		hts->hkey = ht_get_hkey(index, hts->dept, bits, hts->idxt);

		/* must be recursive call */
		ret = __ht_erase(hts, _next, rdata, index);

		if (ret == htf_freed) {
			WRITE_ONCE(htree[key].next, ht_ncnt_set(NULL, ncnt));
			ret = htf_erase;
		}
	}
	return (ret > htf_none) ? htf_erase : htf_none;
}

/**
 * _ht_erase - private function to erase index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @rdata: searching node data to erase
 * @index: user index to erase
 */
static enum ht_flags _ht_erase(struct htree_state *hts,
		struct hash_tree *htree, struct htree_data **rdata, u64 index)
{
	hts->dept = 0;
	hts->hkey = ht_get_hkey(index, 0, hts->sbit, hts->idxt);

	if (__ht_erase(hts, htree, rdata, index) >= htf_erase)
		return htf_erase;

	return htf_none;
}

/**
 * ht_erase - public function to erase index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @index: user index to erase
 *
 * return: rdata: searched node data to erase
 */
struct htree_data *ht_erase(struct htree_state *hts,
			    struct hash_tree *htree, u64 index)
{
	struct htree_data *rdata = NULL;

	if (!htree)
		return NULL;

	if (_ht_erase(hts, htree, &rdata, index) == htf_erase)
		return rdata;

	return NULL;
}
EXPORT_SYMBOL(ht_erase);

/**
 * __ht_free_all - private function to call recursively to free hash tree
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @acnt: freed allocated hash tree count
 * @dcnt: freed node data count
 */
static void __ht_free_all(struct htree_state *hts,
			  struct hash_tree *htree, s32 *acnt, u64 *dcnt)
{
	u8 bits, ncnt;
	u16 k, anum, pnum;
	struct htree_data *pos;
	struct hlist_node *tmp;
	struct hash_tree *_next;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	anum = HTREE_ARRAY_SIZE(bits);

	for (k = 0; k < anum; k++) {
		ncnt = ht_ncnt_get(htree[k].next);
		if (ncnt > 0) {
			bits = ht_bits_from_depth(hts->sbit, hts->dept);
			hlist_for_each_entry_safe(pos, tmp,
					&htree[k].head, hnode) {
				hlist_del(&pos->hnode);
				(*dcnt)++;
			}
		}
		_next = ht_ncnt_pointer(htree[k].next);
		if (_next) {
			hts->dept++;
			pnum = anum;
			/* recursive call */
			__ht_free_all(hts, _next, acnt, dcnt);
			anum = pnum;
			hts->dept--;
		} else {
			continue;
		}
	}
	if (htree) {
		(*acnt)++;
		kfree(htree);	/* free hash table[asize] */
	}
}

/**
 * ht_destroy_lock - public function to free hash tree
 * @hts: htree_state pointer
 * @root: htree_tree pointer(root)
 *
 * this function removes all hash tree, but it does not remove udata.
 */
enum ht_flags ht_destroy_lock(struct htree_state *hts, struct htree_root *root)
{
	s32 acnt = 0;
	u64 dcnt = 0;
	struct hash_tree *htree;

	if (hts->acnt == 0 && hts->dcnt == 0)
		return htf_ok;

	htree = htree_first_rcu(root);
	if (!htree)
		return htf_none;

	hts->dept = 0;

	ht_lock(root);
	__ht_free_all(hts, htree, &acnt, &dcnt);
	RCU_INIT_POINTER(root->ht_first, NULL);
	ht_unlock(root);

	hts->acnt -= acnt;
	hts->dcnt -= dcnt;

	return (hts->dept == 0 && hts->dcnt == 0 && hts->acnt == 0) ?
		htf_ok : htf_none;
}
EXPORT_SYMBOL(ht_destroy_lock);

/**
 * __ht_statis - private function to call recursively to calculate nodes
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @acnt: allocated hash tree count
 * @dcnt: node data count
 */
static void __ht_statis(struct htree_state *hts,
			struct hash_tree *htree, s32 *acnt, u64 *dcnt)
{
	u8 bits, ncnt;
	u16 k, anum, pnum;
	struct hash_tree *_next;

	bits = ht_bits_from_depth(hts->sbit, hts->dept);
	anum = HTREE_ARRAY_SIZE(bits);

	hts->asum += anum;
	(*acnt)++;

	for (k = 0; k < anum; k++) {
		ncnt = ht_ncnt_get(htree[k].next);
		if (ncnt > 0) {
			(*dcnt) += ncnt;
		}
		_next = ht_ncnt_pointer(htree[k].next);
		if (_next) {
			hts->dept++;
			if (hts->dept > hts->dmax)
				hts->dmax = hts->dept;
			pnum = anum;
			/* recursive call */
			__ht_statis(hts, _next, acnt, dcnt);
			anum = pnum;
			hts->dept--;
		} else {
			continue;
		}
	}
}

/**
 * ht_statis - public function to calculate nodes information
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 * @acnt: allocated hash tree count to return
 * @dcnt: node data count to return
 */
void ht_statis(struct htree_state *hts,
	       struct hash_tree *htree, s32 *acnt, u64 *dcnt)
{
	hts->asum = 0;
	hts->dept = 0;
	hts->dmax = 0;

	if (!htree)
		return;

	__ht_statis(hts, htree, acnt, dcnt);
}
EXPORT_SYMBOL(ht_statis);

/**
 * ht_most_index - get most smallest and largest index
 * @hts: htree_state pointer
 * @htree: hash_tree pointer
 *
 * if sorting flag is HTREE_FLAG_ASCD, first hash table has the smallest index.
 * if sorting flag is HTREE_FLAG_DECD, first hash table has the largest index.
 * hts->most has the hash key position, algorithm O(1).
 */
struct htree_data *ht_most_index(struct htree_state *hts, struct hash_tree *htree)
{
	return hlist_entry_safe(htree[hts->most].head.first,
				struct htree_data, hnode);
}
EXPORT_SYMBOL(ht_most_index);

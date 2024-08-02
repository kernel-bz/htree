======================================
Hash Trees (lib/htree) in Linux Kernel
======================================

:Date: August 2, 2024
:Author: JaeJoon Jung <rgbi3307@gmail.com>


Implementation of new Hash Tree
-----------------------------------------------------------------
new Hash Tree Features
-----------------------------------------------------------------
* Very small hash tree structure. [16 Bytes]
* Dynamic memory allocation and free.
* Both 32-bit and 64-bit indexes are possible
* Generate hash keys uniformly based on the index.
* Hash trees are balanced by hash keys, and have no rotation costs.
* Standard deviation of hash key is 4 or less.
* Algorithm O(n) is depth(d) x nodes(c)
* Finding walks is (d x c), min:4, avg:12, max:20
* First hash table has smallest, largest index, algorithm O(1).
* The codes implementing of the algorithm is simple.
* Adjust hash tree depth according to system memory and index nr.
* Hash list nodes use include/linux/list.h, hlist as their base.
-----------------------------------------------------------------

Hash Tree Summary (include/linux/htree.h)
-----------------------------------------------------------------

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

-----------------------------------------------------------------------------
Hash Tree API flow (lib/htree.c, lib/htree-test.c)
-----------------------------------------------------------------------------

*hts = ht_hts_alloc()           /* alloc hts */
ht_hts_clear_init(hts, ...)	/* max nr, type(32/64bits), sort(ASC, DES) */
*htree = ht_table_alloc(hts)    /* alloc first(depth:0) htree */

run_loop() {
	*udata = _data_alloc(index)             /* alloc udata */
	ht_insert(hts, htree, udata->hdata, ..)	/* working data with index */
	ht_erase(hts, htree, index)
	hdata = ht_find(hts, htree, index)
	hdata = ht_most_index(hts, htree)	/* smallest, largest index */
	ht_statis(hts, htree, ...)		/* statistic */
}

htree_erase_all(hts, htree)     /* remove all udata */
ht_destroy(hts, htree)          /* remove all htree */
kfree(hts)                      /* remove hts */

-----------------------------------------------------------------------------
Please refer to the attached PDF for more detailed information.
-----------------------------------------------------------------------------


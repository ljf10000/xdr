#ifndef __UDB_H_554906612bb04a819c8d03c8785a5bbe__
#define __UDB_H_554906612bb04a819c8d03c8785a5bbe__
/******************************************************************************/
enum {
    UNODE_FREE = 0,
    UNODE_TIME = 1,
    UNODE_HASH = 2,
    
    UNODE_END
};

typedef struct {
    time_t time;
    uint32 bkdr;
    byte   idir;
    byte   _[3];
    byte   digest[UFS_DIGEST_SIZE];

    blist_head_t node[UNODE_END];
} udb_entry_t;

static inline udb_entry_t *
udb_ptr2entry(mmap_t *mm, bpointer_t nodeptr, uint32 inode)
{
    return container_of(MMAP_OBJ(mm, nodeptr), udb_entry_t, node[inode]);
}

static inline udb_entry_t *
udb_freeptr2entry(mmap_t *mm, bpointer_t nodefreeptr)
{
    return udb_ptr2entry(mm, nodefreeptr, UNODE_FREE);
}

static inline udb_entry_t *
udb_timeptr2entry(mmap_t *mm, bpointer_t nodetimeptr)
{
    return udb_ptr2entry(mm, nodetimeptr, UNODE_TIME);
}

static inline udb_entry_t *
udb_hashptr2entry(mmap_t *mm, bpointer_t nodehashptr)
{
    return udb_ptr2entry(mm, nodehashptr, UNODE_HASH);
}

static inline bpointer_t
udb_entryptr(mmap_t *mm, udb_entry_t *entry, uint32 inode)
{
    return blist_ptr(mm, &entry->node[inode]);
}

static inline bpointer_t
edb_entry_freeptr(mmap_t *mm, udb_entry_t *entry)
{
    return udb_entryptr(mm, entry, UNODE_FREE);
}

static inline bpointer_t
edb_entry_timeptr(mmap_t *mm, udb_entry_t *entry)
{
    return udb_entryptr(mm, entry, UNODE_TIME);
}

static inline bpointer_t
edb_entry_hashptr(mmap_t *mm, udb_entry_t *entry)
{
    return udb_entryptr(mm, entry, UNODE_HASH);
}

static inline bpointer_t
udb_listptr(mmap_t *mm, uint32 inode)
{    
    return blist_ptr(mm, &udb(mm)->list[inode]);
}

static inline bpointer_t
udb_listfreeptr(mmap_t *mm)
{
    return udb_listptr(mm, UNODE_FREE);
}

static inline bpointer_t
udb_listtimeptr(mmap_t *mm)
{
    return udb_listptr(mm, UNODE_TIME);
}

typedef struct {
    uint32 count;
    uint32 size;
    uint32 hash_size;
    bpointer_t hash;
    bpointer_t entry;
    
    blist_head_t list[UNODE_END-1];
    blist_head_t free;
    blist_head_t time;
} udb_t;

static inline udb_t *
udb(mmap_t *mm)
{
    return (udb_t *)MMAP_OBJ(mm, 0);
}

static inline hash_t *
udb_hash(mmap_t *mm)
{
    return (hash_t *)MMAP_OBJ(mm, udb(mm)->hash);
}

#define UDB_ENTRY(_mm, _db, _idx)   MMAP_OBJ(_mm, (_db)->entry + (_idx)*(_db)->size)

static inline int
udb_init(mmap_t *mm, uint32 size, uint32 hash_size)
{
    udb_t *db = udb(mm);
    if (0==mm->size) {
        return 0;
    }

    db->size        = size;
    db->hash_size   = hash_size;
    db->hash        = OS_PAGESIZE;
    db->entry       = OS_PAGESIZE + hash_size * sizeof(bhash_node_t);
    db->count       = (mm->size - db->entry)/size;

    bpointer_t freeptr = udb_listfreeptr(mm);
    uint32 i;

    INIT_BLIST_HEAD(mm, udb_listtimeptr(mm));
    INIT_BLIST_HEAD(mm, freeptr);
    for (i=0; i<db->count; i++) {
        udb_entry_t *entry = (udb_entry_t *)UDB_ENTRY(mm, db, i);

        blist_add(mm, edb_entry_freeptr(mm, entry), freeptr);
    }

    bhash_init(mm, db->hash, db->hash_size);

    return 0;
}

static inline int
udb_add(mmap_t *mm, bhash_op_t *op)
{
    udb_t *db = udb(mm);
    /*
    * 1. get free-list's first node
    * 2. handle node's data
    * 3. remove node from free-list
    *    add node to time-list's tail
    *    add node to hash
    */

    bpointer_t first = blist_first(mm, udb_listfreeptr(mm));
    if (INVALID_BPOINTER==first) {
        return -ENOMEM;
    }
    udb_entry_t *entry = udb_freeptr2entry(mm, first);
    
    int err = (*op->handle)(mm, db->hash, edb_entry_hashptr(mm, entry));
    if (err<0) {
        return err;
    }

    blist_del(mm, first);
    blist_add_tail(mm, edb_entry_timeptr(mm, entry), udb_listtimeptr(mm));
    bhash_add(mm, db->hash, edb_entry_hashptr(mm, entry), op);
    
    return 0;
}

static inline void
udb_gc(mmap_t *mm, uint32 live)
{
    time_t now = time(NULL);
    udb_t *db = udb(mm);

    while(1) {
        /*
        * 1. get time-list's first node
        * 2. remove node from time-list
        *    remove node from hash
        *    add node to free-list's tail
        */
        bpointer_t tailptr = blist_first(mm, udb_listtimeptr(mm));
        if (INVALID_BPOINTER==tailptr) {
            return;
        }

        udb_entry_t *entry = udb_hashptr2entry(mm, tailptr);
        if (now > entry->time && now - entry->time > live) {
            bhash_del(mm, db->hash, edb_entry_hashptr(mm, entry));
            blist_del(mm, tailptr);
            blist_add_tail(mm, edb_entry_freeptr(mm, entry), udb_listfreeptr(mm));
        } else {
            return;
        }
    }
}

static inline bpointer_t
udb_find(mmap_t *mm, bhash_op_t *op)
{
    return bhash_find(mm, udb(mm)->hash, op);
}

static inline int
udb_update(mmap_t *mm, bhash_op_t *op)
{
    bpointer_t nodeptr = udb_find(mm, op);
    if (INVALID_BPOINTER==nodeptr) {
        return -ENOEXIST;
    }

    udb_entry_t *entry = udb_hashptr2entry(mm, nodeptr);
    
}

/******************************************************************************/
#endif /* __UDB_H_554906612bb04a819c8d03c8785a5bbe__ */


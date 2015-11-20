#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <json.h>
#include <assert.h>

#include "rsyslog.h"
#include "srUtils.h"
#include "errmsg.h"
#include "lookup.h"
#include "msg.h"
#include "rsconf.h"
#include "dirty.h"
#include "unicode-helper.h"

/* definitions for objects we access */
DEFobjStaticHelpers
DEFobjCurrIf(errmsg)
DEFobjCurrIf(statsobj)

#define DYNSTATS_PARAM_NAME "name"
#define DYNSTATS_PARAM_RESETTABLE "resettable"
#define DYNSTATS_PARAM_MAX_CARDINALITY "maxCardinality"
#define DYNSTATS_PARAM_UNUSED_METRIC_LIFE "unusedMetricLife" /* in seconds */

#define DYNSTATS_DEFAULT_RESETTABILITY 1
#define DYNSTATS_DEFAULT_MAX_CARDINALITY 2000
#define DYNSTATS_DEFAULT_UNUSED_METRIC_LIFE 3600 /* seconds */

#define DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH 100
#define DYNSTATS_METRIC_NAME_SEPARATOR ':'
#define DYNSTATS_HASHTABLE_SIZE_OVERPROVISIONING 1.25
#define DYNSTATS_METRIC_TRIE_DEFAULT_HASHTABLE_CAPACITY 8

static struct cnfparamdescr modpdescr[] = {
	{ DYNSTATS_PARAM_NAME, eCmdHdlrString, CNFPARAM_REQUIRED },
	{ DYNSTATS_PARAM_RESETTABLE, eCmdHdlrBinary, 0 },
	{ DYNSTATS_PARAM_MAX_CARDINALITY, eCmdHdlrPositiveInt, 0},
	{ DYNSTATS_PARAM_UNUSED_METRIC_LIFE, eCmdHdlrPositiveInt, 0} /* in minutes */
};

static struct cnfparamblk modpblk =
{ CNFPARAMBLK_VERSION,
  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
  modpdescr
};

rsRetVal
dynstatsClassInit(void) {
	DEFiRet;
	CHKiRet(objGetObjInterface(&obj));
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(statsobj, CORE_COMPONENT));
finalize_it:
	RETiRet;
}

static inline void
dynstats_destroyCtr(dynstats_bucket_t *b, dynstats_ctr_t *ctr, uint8_t destructStatsCtr) {
	if (destructStatsCtr) {
		statsobj.DestructCounter(b->stats, ctr->pCtr);
	}
	free(ctr->metric);
	free(ctr);
}

static inline void
dynstats_destroyMetricNode(dynstats_bucket_t *b, dynstats_metric_node_t *n, uint8_t destructStatsCtr);

static inline void
dynstats_destroyMetricEntry(dynstats_bucket_t *b, dynstats_metric_entry_t *e,  uint8_t destructStatsCtr) {
    if (ustrlen(e->k) == 0) {
        dynstats_destroyCtr(b, e->d.ctr, destructStatsCtr);
    } else {
        dynstats_destroyMetricNode(b, e->d.nxt, destructStatsCtr);
    }
	free(e->k);
    free(e);
}

static inline void
dynstats_destroyMetricNode(dynstats_bucket_t *b, dynstats_metric_node_t *n, uint8_t destructStatsCtr) {
    dynstats_metric_entry_t *e;

    hdestroy_r(&n->table);
    while(1) {
		e = SLIST_FIRST(&n->entries);
		if (e == NULL) {
			break;
		} else {
			SLIST_REMOVE_HEAD(&n->entries, link);
			dynstats_destroyMetricEntry(b, e, destructStatsCtr);
		}
	}
    pthread_rwlock_destroy(&n->lock);
    free(n);
}

static inline void /* assumes exclusive access to bucket */
dynstats_destroyMetrics(dynstats_bucket_t *b) {
	statsobj.DestructAllCounters(b->stats);
    dynstats_destroyMetricNode(b, b->root, 0);
	STATSCOUNTER_BUMP(b->ctrMetricsPurged, b->mutCtrMetricsPurged, b->metricCount);
}

void
dynstats_destroyBucket(dynstats_bucket_t* b) {
	dynstats_buckets_t *bkts;

	bkts = &loadConf->dynstats_buckets;

	pthread_rwlock_wrlock(&b->lock);
	dynstats_destroyMetrics(b);
	statsobj.Destruct(&b->stats);
	free(b->name);
	pthread_rwlock_unlock(&b->lock);
	pthread_rwlock_destroy(&b->lock);
	pthread_mutex_destroy(&b->mutMetricCount);
	statsobj.DestructCounter(bkts->global_stats, b->pOpsOverflowCtr);
	statsobj.DestructCounter(bkts->global_stats, b->pNewMetricAddCtr);
	statsobj.DestructCounter(bkts->global_stats, b->pNoMetricCtr);
	statsobj.DestructCounter(bkts->global_stats, b->pMetricsPurgedCtr);
	free(b);
}

static rsRetVal
dynstats_addBucketMetrics(dynstats_buckets_t *bkts, dynstats_bucket_t *b, const uchar* name) {
	uchar *metric_name_buff, *metric_suffix;
	const uchar *suffix_litteral;
	int name_len;
	DEFiRet;

	name_len = ustrlen(name);
	CHKmalloc(metric_name_buff = malloc(name_len * sizeof(uchar) + DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH));

	ustrncpy(metric_name_buff, name, name_len);
	metric_suffix = metric_name_buff + name_len;
	*metric_suffix = DYNSTATS_METRIC_NAME_SEPARATOR;
	metric_suffix++;

	suffix_litteral = UCHAR_CONSTANT("ops_overflow");
	ustrncpy(metric_suffix, suffix_litteral, DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH);
	STATSCOUNTER_INIT(b->ctrOpsOverflow, b->mutCtrOpsOverflow);
	CHKiRet(statsobj.AddManagedCounter(bkts->global_stats, metric_name_buff, ctrType_IntCtr,
									   CTR_FLAG_RESETTABLE, &(b->ctrOpsOverflow), &b->pOpsOverflowCtr));

	suffix_litteral = UCHAR_CONSTANT("new_metric_add");
	ustrncpy(metric_suffix, suffix_litteral, DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH);
	STATSCOUNTER_INIT(b->ctrNewMetricAdd, b->mutCtrNewMetricAdd);
	CHKiRet(statsobj.AddManagedCounter(bkts->global_stats, metric_name_buff, ctrType_IntCtr,
									   CTR_FLAG_RESETTABLE, &(b->ctrNewMetricAdd), &b->pNewMetricAddCtr));

	suffix_litteral = UCHAR_CONSTANT("no_metric");
	ustrncpy(metric_suffix, suffix_litteral, DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH);
	STATSCOUNTER_INIT(b->ctrNoMetric, b->mutCtrNoMetric);
	CHKiRet(statsobj.AddManagedCounter(bkts->global_stats, metric_name_buff, ctrType_IntCtr,
									   CTR_FLAG_RESETTABLE, &(b->ctrNoMetric), &b->pNoMetricCtr));

	suffix_litteral = UCHAR_CONSTANT("metrics_purged");
	ustrncpy(metric_suffix, suffix_litteral, DYNSTATS_MAX_BUCKET_NS_METRIC_LENGTH);
	STATSCOUNTER_INIT(b->ctrMetricsPurged, b->mutCtrMetricsPurged);
	CHKiRet(statsobj.AddManagedCounter(bkts->global_stats, metric_name_buff, ctrType_IntCtr,
									   CTR_FLAG_RESETTABLE, &(b->ctrMetricsPurged), &b->pMetricsPurgedCtr));
finalize_it:
	free(metric_name_buff);
	if (iRet != RS_RET_OK) {
		if (b->pOpsOverflowCtr != NULL) {
			statsobj.DestructCounter(bkts->global_stats, b->pOpsOverflowCtr);
		}
		if (b->pNewMetricAddCtr != NULL) {
			statsobj.DestructCounter(bkts->global_stats, b->pNewMetricAddCtr);
		}
		if (b->pNoMetricCtr != NULL) {
			statsobj.DestructCounter(bkts->global_stats, b->pNoMetricCtr);
		}
		if (b->pMetricsPurgedCtr != NULL) {
			statsobj.DestructCounter(bkts->global_stats, b->pMetricsPurgedCtr);
		}
	}
	RETiRet;
}

static inline rsRetVal
dynstats_createMetricNode(dynstats_metric_node_t **node) {
    dynstats_metric_node_t *n;
    uint8_t lock_initialized;
    DEFiRet;

    lock_initialized = 0;

    CHKmalloc(n = calloc(1, sizeof(dynstats_metric_node_t)));
    n->capacity = DYNSTATS_METRIC_TRIE_DEFAULT_HASHTABLE_CAPACITY;
    pthread_rwlock_init(&n->lock, NULL);
    lock_initialized = 1;
    if (! hcreate_r(n->capacity, &n->table)) {
		ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
	}
    SLIST_INIT(&n->entries);

    *node = n;
finalize_it:
    if (iRet != RS_RET_OK) {
        hdestroy_r(&n->table);
        if (lock_initialized) {
            pthread_rwlock_destroy(&n->lock);
        }
        free(n);
    }

    RETiRet;
}

static inline rsRetVal
dynstats_createMetrics(dynstats_bucket_t *b) {
    DEFiRet;
    b->root = NULL;
    CHKiRet(dynstats_createMetricNode(&b->root));
finalize_it:
    RETiRet;
}

static rsRetVal
dynstats_resetBucket(dynstats_bucket_t *b, uint8_t do_purge) {
	DEFiRet;
	pthread_rwlock_wrlock(&b->lock);
	if (do_purge) {
		dynstats_destroyMetrics(b);
	}
	ATOMIC_STORE_0_TO_INT(&b->metricCount, &b->mutMetricCount);
	SLIST_INIT(&b->ctrs);
    CHKiRet(dynstats_createMetrics(b));
	timeoutComp(&b->metricCleanupTimeout, b->unusedMetricLife);
finalize_it:
	pthread_rwlock_unlock(&b->lock);
	if (iRet != RS_RET_OK) {
		statsobj.Destruct(&b->stats);
	}
	RETiRet;
}

static inline void
dynstats_resetIfExpired(dynstats_bucket_t *b) {
	long timeout;
	pthread_rwlock_rdlock(&b->lock);
	timeout = timeoutVal(&b->metricCleanupTimeout);
	pthread_rwlock_unlock(&b->lock);
	if (timeout == 0) {
		errmsg.LogMsg(0, RS_RET_TIMED_OUT, LOG_INFO, "dynstats: bucket '%s' is being reset", b->name);
		dynstats_resetBucket(b, 1);
	}
}

static void
dynstats_readCallback(statsobj_t *ignore, void *b) {
	dynstats_buckets_t *bkts;
	bkts = &loadConf->dynstats_buckets;

	pthread_rwlock_rdlock(&bkts->lock);
	dynstats_resetIfExpired((dynstats_bucket_t *) b);
	pthread_rwlock_unlock(&bkts->lock);
}

static inline rsRetVal
dynstats_initNewBucketStats(dynstats_bucket_t *b) {
	DEFiRet;
	
	CHKiRet(statsobj.Construct(&b->stats));
	CHKiRet(statsobj.SetOrigin(b->stats, UCHAR_CONSTANT("dynstats.bucket")));
	CHKiRet(statsobj.SetName(b->stats, b->name));
	statsobj.SetReadNotifier(b->stats, dynstats_readCallback, b);
	CHKiRet(statsobj.ConstructFinalize(b->stats));
	
finalize_it:
	RETiRet;
}

static rsRetVal
dynstats_newBucket(const uchar* name, uint8_t resettable, uint32_t maxCardinality, uint32_t unusedMetricLife) {
	dynstats_bucket_t *b;
	dynstats_buckets_t *bkts;
	uint8_t lock_initialized, metric_count_mutex_initialized;
	pthread_rwlockattr_t bucket_lock_attr;
	DEFiRet;

	lock_initialized = metric_count_mutex_initialized = 0;
	b = NULL;
	
	bkts = &loadConf->dynstats_buckets;

	if (bkts->initialized) {
		CHKmalloc(b = calloc(1, sizeof(dynstats_bucket_t)));
		b->resettable = resettable;
		b->maxCardinality = maxCardinality;
		b->unusedMetricLife = 1000 * unusedMetricLife; 
		CHKmalloc(b->name = ustrdup(name));

		pthread_rwlockattr_init(&bucket_lock_attr);
		pthread_rwlockattr_setkind_np(&bucket_lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

		pthread_rwlock_init(&b->lock, &bucket_lock_attr);
		lock_initialized = 1;
		pthread_mutex_init(&b->mutMetricCount, NULL);
		metric_count_mutex_initialized = 1;

		CHKiRet(dynstats_initNewBucketStats(b));

		CHKiRet(dynstats_resetBucket(b, 0));

		CHKiRet(dynstats_addBucketMetrics(bkts, b, name));

		pthread_rwlock_wrlock(&bkts->lock);
		SLIST_INSERT_HEAD(&bkts->list, b, link);
		pthread_rwlock_unlock(&bkts->lock);
	} else {
		errmsg.LogError(0, RS_RET_INTERNAL_ERROR, "dynstats: bucket creation failed, as global-initialization of buckets was unsuccessful");
		ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
	}
finalize_it:
	if (iRet != RS_RET_OK) {
		if (metric_count_mutex_initialized) {
			pthread_mutex_destroy(&b->mutMetricCount);
		}
		if (lock_initialized) {
			pthread_rwlock_destroy(&b->lock);
		}
		if (b != NULL) {
			free(b->name);
			free(b);
		}
	}
	RETiRet;
}

rsRetVal
dynstats_processCnf(struct cnfobj *o) {
	struct cnfparamvals *pvals;
	short i;
	uchar *name;
	uint8_t resettable = DYNSTATS_DEFAULT_RESETTABILITY;
	uint32_t maxCardinality = DYNSTATS_DEFAULT_MAX_CARDINALITY;
	uint32_t unusedMetricLife = DYNSTATS_DEFAULT_UNUSED_METRIC_LIFE;
	DEFiRet;

	pvals = nvlstGetParams(o->nvlst, &modpblk, NULL);
	if(pvals == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}
	
	for(i = 0 ; i < modpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, DYNSTATS_PARAM_NAME)) {
			CHKmalloc(name = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL));
		} else if (!strcmp(modpblk.descr[i].name, DYNSTATS_PARAM_RESETTABLE)) {
			resettable = (pvals[i].val.d.n != 0);
		} else if (!strcmp(modpblk.descr[i].name, DYNSTATS_PARAM_MAX_CARDINALITY)) {
			maxCardinality = (uint32_t) pvals[i].val.d.n;
		} else if (!strcmp(modpblk.descr[i].name, DYNSTATS_PARAM_UNUSED_METRIC_LIFE)) {
			unusedMetricLife = (uint32_t) pvals[i].val.d.n;
		} else {
			dbgprintf("dyn_stats: program error, non-handled "
					  "param '%s'\n", modpblk.descr[i].name);
		}
	}
	CHKiRet(dynstats_newBucket(name, resettable, maxCardinality, unusedMetricLife));

finalize_it:
	free(name);
	cnfparamvalsDestruct(pvals, &modpblk);
	RETiRet;
}

rsRetVal
dynstats_initCnf(dynstats_buckets_t *bkts) {
	DEFiRet;

	bkts->initialized = 0;
	
	SLIST_INIT(&bkts->list);
	CHKiRet(statsobj.Construct(&bkts->global_stats));
	CHKiRet(statsobj.SetOrigin(bkts->global_stats, UCHAR_CONSTANT("dynstats")));
	CHKiRet(statsobj.SetName(bkts->global_stats, UCHAR_CONSTANT("global")));
	CHKiRet(statsobj.ConstructFinalize(bkts->global_stats));
	pthread_rwlock_init(&bkts->lock, NULL);

	bkts->initialized = 1;
	
finalize_it:
	if (iRet != RS_RET_OK) {
		statsobj.Destruct(&bkts->global_stats);
	}
	RETiRet;
}

void
dynstats_destroyAllBuckets() {
	dynstats_buckets_t *bkts;
	dynstats_bucket_t *b;
	bkts = &loadConf->dynstats_buckets;
	if (bkts->initialized) {
		pthread_rwlock_wrlock(&bkts->lock);
		while(1) {
			b = SLIST_FIRST(&bkts->list);
			if (b == NULL) {
				break;
			} else {
				SLIST_REMOVE_HEAD(&bkts->list, link);
				dynstats_destroyBucket(b);
			}
		}
		pthread_rwlock_unlock(&bkts->lock);
		pthread_rwlock_destroy(&bkts->lock);
	}
}

dynstats_bucket_t *
dynstats_findBucket(const uchar* name) {
	dynstats_buckets_t *bkts;
	dynstats_bucket_t *b;
	bkts = &loadConf->dynstats_buckets;
	if (bkts->initialized) {
		pthread_rwlock_rdlock(&bkts->lock);
		SLIST_FOREACH(b, &bkts->list, link) {
			if (! ustrcmp(name, b->name)) {
				break;
			}
		}
		pthread_rwlock_unlock(&bkts->lock);
	} else {
		b = NULL;
		errmsg.LogError(0, RS_RET_INTERNAL_ERROR, "dynstats: bucket lookup failed, as global-initialization of buckets was unsuccessful");
	}

	return b;
}

static rsRetVal
dynstats_createCtr(dynstats_bucket_t *b, const uchar* metric, dynstats_ctr_t **ctr) {
	DEFiRet;
	
	CHKmalloc(*ctr = calloc(1, sizeof(dynstats_ctr_t)));
	CHKmalloc((*ctr)->metric = ustrdup(metric));
	STATSCOUNTER_INIT((*ctr)->ctr, (*ctr)->mutCtr);
	CHKiRet(statsobj.AddManagedCounter(b->stats, metric, ctrType_IntCtr,
									   b->resettable, &(*ctr)->ctr, &(*ctr)->pCtr));
finalize_it:
	if (iRet != RS_RET_OK) {
		free((*ctr)->metric);
		free(*ctr);
		*ctr = NULL;
	}
	RETiRet;
}

static inline rsRetVal
dynstats_findOrCreateCtr(dynstats_bucket_t *b, dynstats_metric_node_t *n, dynstats_ctr_t **pCtr, uchar *metric, int metric_len, int remaining_metric_len);

static inline rsRetVal
dynstats_proceedFindOrCreateCtr(dynstats_bucket_t *b, ENTRY *entry, dynstats_ctr_t **pCtr, uchar *metric, int metric_len, int remaining_metric_len) {
	dynstats_metric_entry_t *e;
	DEFiRet;
	e = (dynstats_metric_entry_t *)entry->data;
	if (remaining_metric_len > 0) {
		CHKiRet(dynstats_findOrCreateCtr(b, e->d.nxt, pCtr, metric, metric_len, remaining_metric_len - 1));
	} else {
		*pCtr = e->d.ctr;
	}
finalize_it:
	RETiRet;
}

static inline rsRetVal
dynstats_createMetricNodeEntry(dynstats_bucket_t *b, dynstats_metric_entry_t **pEntry, uchar *key) {
	dynstats_metric_node_t *nxt;
	dynstats_metric_entry_t *e;
	DEFiRet;
	CHKiRet(dynstats_createMetricNode(&nxt));
	CHKmalloc(e = calloc(1, sizeof(dynstats_metric_entry_t)));
	e->d.nxt = nxt;
	e->k = ustrdup(key);
	*pEntry = e;
finalize_it:
	if (iRet != RS_RET_OK) {
		/*dont worry about destroying counters, because its just cleanup for failed create, no counters can exist anyway*/
		dynstats_destroyMetricNode(b, nxt, 0);
	}
	RETiRet;
}

static inline rsRetVal
dynstats_createMetricCtrEntry(dynstats_metric_entry_t **pEntry, dynstats_bucket_t *b, uchar *metric, uchar *key) {
	dynstats_metric_node_t *nxt;
	dynstats_metric_entry_t *e;
	dynstats_ctr_t *ctr;
	DEFiRet;
	CHKiRet(dynstats_createCtr(b, metric, &ctr));
	CHKmalloc(e = calloc(1, sizeof(dynstats_metric_entry_t)));
	e->d.ctr = ctr;
	e->k = ustrdup(key);
	*pEntry = e;
finalize_it:
	if (iRet != RS_RET_OK) {
		dynstats_destroyCtr(b, ctr, 1);
	}
	RETiRet;
}

static inline rsRetVal
dynstats_insertToMetricNodeTable(dynstats_metric_entry_t *e, dynstats_metric_node_t *n) {
	ENTRY lookup;
	ENTRY *entry;
	int created;
	DEFiRet;

	lookup.key = e->k;
	lookup.data = e;
	created = hsearch_r(lookup, ENTER, &entry, &n->table);
	if (! created) {
		ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
	}

finalize_it:
	RETiRet;
}

static inline rsRetVal
dynstats_insertToMetricNode(dynstats_metric_entry_t *e, dynstats_metric_node_t *n) {
	DEFiRet;

	CHKiRet(dynstats_insertToMetricNodeTable(e, n));
	SLIST_INSERT_HEAD(&n->entries, e, link);
	n->size++;
	
finalize_it:
	RETiRet;
}

static inline void
dynstats_rehashMetricNodeEntries(dynstats_metric_node_t *n) {
	dynstats_metric_entry_t *e;
	SLIST_FOREACH(e, &n->entries, link) {
		dynstats_insertToMetricNodeTable(e, n);
	}
}


static inline rsRetVal
dynstats_initMetric(dynstats_bucket_t *b, dynstats_metric_node_t *n, dynstats_ctr_t **pCtr, uchar *metric, int metric_len, int remaining_metric_len) {
	ENTRY *entry;
    ENTRY lookup;
	uchar key[2];
    uchar c;
	int found;
	uint8_t locked;
	dynstats_metric_entry_t *e;
	htable new_table;
	int new_table_capacity;
	DEFiRet;

	locked = 0;
	e = NULL;

	if (ATOMIC_FETCH_32BIT(&b->metricCount, &b->mutMetricCount) >= b->maxCardinality) {
		ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
	}

	if (remaining_metric_len > 0) {
        key[0] =  metric[metric_len - remaining_metric_len];
        key[1] = '\0';
    } else {
        key[0] = '\0';
    }
	lookup.key = key;
	
	pthread_rwlock_wrlock(&n->lock);
	locked = 1;
	found = hsearch_r(lookup, FIND, &entry, &n->table);
	if (found) {
		pthread_rwlock_unlock(&n->lock);
		pthread_rwlock_rdlock(&n->lock);
		found = hsearch_r(lookup, FIND, &entry, &n->table); /* because rehash may have killed the old table */
		CHKiRet(dynstats_proceedFindOrCreateCtr(b, entry, pCtr, metric, metric_len, remaining_metric_len));
	} else {
		if (n->size == n->capacity) {/* double the size and rehash */
			new_table_capacity = n->capacity * 2;
			memset(&new_table, 0, sizeof(htable));
			if (! hcreate_r(new_table_capacity, &new_table)) {
				ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
			}
			hdestroy_r(&n->table);
			n->capacity = new_table_capacity;
			n->table = new_table;
			dynstats_rehashMetricNodeEntries(n);
		}
		if (remaining_metric_len > 0) {
			CHKiRet(dynstats_createMetricNodeEntry(b, &e, key));
			CHKiRet(dynstats_insertToMetricNode(e, n));
			pthread_rwlock_unlock(&n->lock);
			pthread_rwlock_rdlock(&n->lock);
			CHKiRet(dynstats_initMetric(b, e->d.nxt, pCtr, metric, metric_len, remaining_metric_len - 1));
		} else {
			CHKiRet(dynstats_createMetricCtrEntry(&e, b, metric, key));
			CHKiRet(dynstats_insertToMetricNode(e, n));
			ATOMIC_INC(&b->metricCount, &b->mutMetricCount);
			STATSCOUNTER_INC(b->ctrNewMetricAdd, b->mutCtrNewMetricAdd);
			*pCtr = e->d.ctr;
		}
	}
finalize_it:
	if (locked) {
		pthread_rwlock_unlock(&n->lock);
	}
	if (iRet != RS_RET_OK) {
		if (e != NULL) {
			dynstats_destroyMetricEntry(b, e, 1);
		}
		*pCtr = NULL;
		iRet = RS_RET_OK;
	}
	RETiRet;
}

static inline rsRetVal
dynstats_findOrCreateCtr(dynstats_bucket_t *b, dynstats_metric_node_t *n, dynstats_ctr_t **pCtr, uchar *metric, int metric_len, int remaining_metric_len) {
    uchar c;
    ENTRY lookup;
    ENTRY *entry;
    uchar key[2];
    int found;
    dynstats_metric_entry_t *e;
    uint8_t locked;
    DEFiRet;

    locked = 0;
    if (remaining_metric_len > 0) {
        key[0] =  metric[metric_len - remaining_metric_len];
        key[1] = '\0';
    } else {
        key[0] = '\0';
    }

    lookup.key = key;
    pthread_rwlock_rdlock(&n->lock);
    locked = 1;
    found = hsearch_r(lookup, FIND, &entry, &n->table);
    if (found) {
        CHKiRet(dynstats_proceedFindOrCreateCtr(b, entry, pCtr, metric, metric_len, remaining_metric_len));
    } else {
        pthread_rwlock_unlock(&n->lock);
		locked = 0;
		CHKiRet(dynstats_initMetric(b, n, pCtr, metric, metric_len, remaining_metric_len));
    }
finalize_it:
    if (locked) {
        pthread_rwlock_unlock(&n->lock);
    }        
    RETiRet;
}


static inline rsRetVal
dynstats_incCtr(dynstats_bucket_t *b, uchar *metric) {
    dynstats_ctr_t *ctr;
	int metric_len;
    DEFiRet;
	metric_len = ustrlen(metric);
    pthread_rwlock_rdlock(&b->lock);
    CHKiRet(dynstats_findOrCreateCtr(b, b->root, &ctr, metric, metric_len, metric_len));
	if (ctr == NULL) {
		ABORT_FINALIZE(RS_RET_NONE);
	}
    STATSCOUNTER_INC(ctr->ctr, ctr->mutCtr);
finalize_it:
    pthread_rwlock_unlock(&b->lock);
    RETiRet;
}

rsRetVal
dynstats_inc(dynstats_bucket_t *b, uchar* metric) {
	int succeed;
	DEFiRet;

	if (ustrlen(metric) == 0) {
		STATSCOUNTER_INC(b->ctrNoMetric, b->mutCtrNoMetric);
		FINALIZE;
	}

	CHKiRet(dynstats_incCtr(b, metric));

finalize_it:

	if (iRet != RS_RET_OK) {
		STATSCOUNTER_INC(b->ctrOpsOverflow, b->mutCtrOpsOverflow);
	}
	RETiRet;
}


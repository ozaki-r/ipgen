#ifndef _SEQTABLE_H_
#define _SEQTABLE_H_

struct sequence_record {
	uint32_t seq;

	/* filled by caller */
	uint32_t flowid;
	uint32_t flowseq;
	struct timespec ts;
};

#define SEQTABLE_NRECORD	(128*1024)	/* must be 2^n */
struct sequence_table {
	uint32_t sq_nextseq;
	struct sequence_record sq_record[SEQTABLE_NRECORD];
};

struct sequence_table *seqtable_new(void);
void seqtable_init(struct sequence_table *);
void seqtable_delete(struct sequence_table *);
void seqtable_dump(struct sequence_table *);

static inline struct sequence_record *
seqtable_get(struct sequence_table *sq, uint32_t seq)
{
	uint32_t i;

	i = seq & (SEQTABLE_NRECORD - 1);
	return &sq->sq_record[i];
}

static inline struct sequence_record *
seqtable_prep(struct sequence_table *sq)
{
	struct sequence_record *record;
	uint32_t n;

	n = sq->sq_nextseq++;

	record = seqtable_get(sq, n);
	record->seq = n;

	return record;
}

#endif /* _SEQTABLE_H_ */

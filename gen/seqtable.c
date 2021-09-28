#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#include "seqtable.h"

struct sequence_table *
seqtable_new(void)
{
	struct sequence_table *sq;

	sq = malloc(sizeof(struct sequence_table));
	if (sq != NULL)
		seqtable_init(sq);

	return sq;
}

void
seqtable_init(struct sequence_table *sq)
{
	memset(sq, 0, sizeof(*sq));
}

void
seqtable_delete(struct sequence_table *sq)
{
	free(sq);
}

void
seqtable_dump(struct sequence_table *sq)
{
	int i;

	printf("================================================================================\n");
	printf("sq_nextseq         = %u\n", sq->sq_nextseq);

	for (i = 0; i < SEQTABLE_NRECORD; i++) {
		printf("sq_record[%04d].seq=%u\n",
		    i, sq->sq_record[i].seq);
	}
}

#if 0	/* TEST */
int
main(int argc, char *argv[])
{
	int i, j;
	struct sequence_table seqtbl;
	struct sequence_record *record;

	(void)&argc;
	(void)&argv;

	seqtable_init(&seqtbl);
	seqtable_dump(&seqtbl);

#if 1
	for (i = 0; i < 10000; i++) {
		printf("prep\n");
		record = seqtable_prep(&seqtbl);
		seqtable_dump(&seqtbl);

		for (j = i - 40; j < i - 20; j++) {
			record = seqtable_get(&seqtbl, j);
			printf("get(%u).seq=%u\n", j, record->seq);
		}
	}
	exit(1);
#endif

}
#endif


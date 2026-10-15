// SPDX-License-Identifier: GPL-2.0-only
/* Compare guest RDRAND/RDSEED records with memento.prn/v1 host JSONL. */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guest_record.h"

struct key {
	uint64_t value;
	uint8_t inst;
	uint8_t bits;
};

static int key_cmp(const void *a, const void *b)
{
	const struct key *x = a, *y = b;

	if (x->inst != y->inst)
		return x->inst < y->inst ? -1 : 1;
	if (x->bits != y->bits)
		return x->bits < y->bits ? -1 : 1;
	if (x->value != y->value)
		return x->value < y->value ? -1 : 1;
	return 0;
}

static int append_key(struct key **keys, size_t *count, size_t *capacity,
		      struct key value)
{
	struct key *resized;

	if (*count == *capacity) {
		*capacity = *capacity ? *capacity * 2 : 1024;
		resized = realloc(*keys, *capacity * sizeof(**keys));
		if (!resized) {
			perror("realloc");
			return -1;
		}
		*keys = resized;
	}
	(*keys)[(*count)++] = value;
	return 0;
}

static struct key *load_guest(const char *path, size_t *out_n,
			      uint64_t *out_total, uint64_t *out_cf0)
{
	FILE *fp = fopen(path, "rb");
	struct guest_record rec;
	struct key *keys = NULL;
	size_t count = 0, capacity = 0;
	uint64_t total = 0, cf0 = 0;

	if (!fp) {
		perror("open guest-log");
		return NULL;
	}
	for (;;) {
		size_t bytes = fread(&rec, 1, sizeof(rec), fp);

		if (bytes == 0) {
			if (ferror(fp)) {
				perror("read guest-log");
				goto fail;
			}
			break;
		}
		if (bytes != sizeof(rec)) {
			fprintf(stderr, "partial guest record\n");
			goto fail;
		}
		if ((rec.inst != GUEST_INST_RDRAND && rec.inst != GUEST_INST_RDSEED) ||
		    (rec.bits != 16 && rec.bits != 32 && rec.bits != 64) ||
		    rec.cf > 1 || rec.reserved != 0) {
			fprintf(stderr, "invalid guest record\n");
			goto fail;
		}
		total++;
		if (!rec.cf) {
			cf0++;
			continue;
		}
		if (rec.bits == 16)
			rec.value &= UINT64_C(0xffff);
		else if (rec.bits == 32)
			rec.value &= UINT64_C(0xffffffff);
		if (append_key(&keys, &count, &capacity,
			       (struct key){rec.value, rec.inst, rec.bits}))
			goto fail;
	}
	fclose(fp);
	*out_n = count;
	*out_total = total;
	*out_cf0 = cf0;
	return keys;

fail:
	free(keys);
	fclose(fp);
	return NULL;
}

/* The producer is encoding/json, so matching its compact field form is safe. */
static int json_string(const char *line, const char *field, char *out,
		       size_t out_size)
{
	char needle[64];
	const char *start, *end;
	size_t length;

	if (snprintf(needle, sizeof(needle), "\"%s\":\"", field) >=
	    (int)sizeof(needle))
		return -1;
	start = strstr(line, needle);
	if (!start)
		return -1;
	start += strlen(needle);
	end = strchr(start, '"');
	if (!end)
		return -1;
	length = (size_t)(end - start);
	if (!length || length >= out_size)
		return -1;
	memcpy(out, start, length);
	out[length] = '\0';
	return 0;
}

static int json_uint(const char *line, const char *field, unsigned long *out)
{
	char needle[64], *end;
	const char *start;

	if (snprintf(needle, sizeof(needle), "\"%s\":", field) >=
	    (int)sizeof(needle))
		return -1;
	start = strstr(line, needle);
	if (!start)
		return -1;
	start += strlen(needle);
	errno = 0;
	*out = strtoul(start, &end, 10);
	return errno == 0 && end != start ? 0 : -1;
}

static struct key *load_host(const char *path, size_t *out_n)
{
	FILE *fp = fopen(path, "r");
	char *line = NULL;
	size_t line_capacity = 0, count = 0, capacity = 0;
	struct key *keys = NULL;

	if (!fp) {
		perror("open host-log");
		return NULL;
	}
	while (getline(&line, &line_capacity, fp) != -1) {
		char schema[32], source[16], operation[16], hex[17], *end;
		unsigned long bits;
		uint64_t value;
		uint8_t inst;

		if (line[0] == '\n' && line[1] == '\0')
			continue;
		if (json_string(line, "schema", schema, sizeof(schema)) ||
		    strcmp(schema, "memento.prn/v1") ||
		    json_string(line, "source", source, sizeof(source)) ||
		    strcmp(source, "cpu") ||
		    json_string(line, "operation", operation, sizeof(operation)) ||
		    json_string(line, "value_hex", hex, sizeof(hex)) ||
		    json_uint(line, "operand_bits", &bits)) {
			fprintf(stderr, "invalid host memento.prn/v1 record\n");
			goto fail;
		}
		if (!strcmp(operation, "rdrand"))
			inst = GUEST_INST_RDRAND;
		else if (!strcmp(operation, "rdseed"))
			inst = GUEST_INST_RDSEED;
		else {
			fprintf(stderr, "invalid host instruction\n");
			goto fail;
		}
		if ((bits != 16 && bits != 32 && bits != 64) ||
		    strlen(hex) != bits / 4) {
			fprintf(stderr, "invalid host width/value length\n");
			goto fail;
		}
		errno = 0;
		value = strtoull(hex, &end, 16);
		if (errno || end == hex || *end != '\0') {
			fprintf(stderr, "invalid host hex value\n");
			goto fail;
		}
		if (append_key(&keys, &count, &capacity,
			       (struct key){value, inst, (uint8_t)bits}))
			goto fail;
	}
	if (ferror(fp)) {
		perror("read host-log");
		goto fail;
	}
	free(line);
	fclose(fp);
	*out_n = count;
	return keys;

fail:
	free(keys);
	free(line);
	fclose(fp);
	return NULL;
}

int main(int argc, char *argv[])
{
	const char *guest_path = NULL, *host_path = NULL;
	struct key *guest = NULL, *host = NULL;
	size_t guest_n = 0, host_n = 0, i = 0, j = 0;
	uint64_t guest_total = 0, guest_cf0 = 0;
	uint64_t matched = 0, missing = 0, extra = 0;
	int opt;
	static const struct option options[] = {
		{"guest-log", required_argument, NULL, 'g'},
		{"host-log", required_argument, NULL, 'H'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	while ((opt = getopt_long(argc, argv, "g:H:h", options, NULL)) != -1) {
		switch (opt) {
		case 'g': guest_path = optarg; break;
		case 'H': host_path = optarg; break;
		case 'h':
			printf("usage: %s --guest-log FILE --host-log FILE\n", argv[0]);
			return 0;
		default:
			return 2;
		}
	}
	if (!guest_path || !host_path || optind != argc) {
		fprintf(stderr, "--guest-log and --host-log are required\n");
		return 2;
	}
	guest = load_guest(guest_path, &guest_n, &guest_total, &guest_cf0);
	if (!guest && guest_total == 0)
		return 1;
	host = load_host(host_path, &host_n);
	if (!host && host_n == 0) {
		free(guest);
		return 1;
	}
	qsort(guest, guest_n, sizeof(*guest), key_cmp);
	qsort(host, host_n, sizeof(*host), key_cmp);
	while (i < guest_n && j < host_n) {
		int comparison = key_cmp(&guest[i], &host[j]);

		if (!comparison) { matched++; i++; j++; }
		else if (comparison < 0) { missing++; i++; }
		else { extra++; j++; }
	}
	missing += guest_n - i;
	extra += host_n - j;
	printf("guest records: %zu (cf=1), cf=0: %llu, total: %llu\n",
	       guest_n, (unsigned long long)guest_cf0,
	       (unsigned long long)guest_total);
	printf("host records:  %zu\nmatched: %llu\nmissing: %llu\nextra: %llu\n",
	       host_n, (unsigned long long)matched, (unsigned long long)missing,
	       (unsigned long long)extra);
	free(guest);
	free(host);
	return missing == 0 ? 0 : 1;
}

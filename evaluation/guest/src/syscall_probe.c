// SPDX-License-Identifier: GPL-2.0-only
/*
 * Emit ground-truth JSONL for read(2) on Linux random devices and
 * getrandom(2). This helper never encrypts, renames, or removes user files.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_LIMIT 128U
#define MAX_REQUEST (1024U * 1024U)
#define MAX_THREADS 256U

enum operation {
	OP_READ_RANDOM,
	OP_READ_URANDOM,
	OP_GETRANDOM,
};

enum api {
	API_RAW,
	API_LIBC,
};

enum mode {
	MODE_NORMAL,
	MODE_EFAULT,
	MODE_INVALID_FD,
	MODE_REGULAR_FILE,
};

struct options {
	enum operation operation;
	enum api api;
	enum mode mode;
	size_t size;
	unsigned int threads;
	unsigned int iterations;
	unsigned int flags;
	unsigned int start_delay_ms;
	unsigned int hold_ms;
	const char *output_path;
	char regular_dir[PATH_MAX];
	char regular_path[PATH_MAX];
};

struct worker {
	const struct options *options;
	unsigned int index;
	int failures;
};

static FILE *output;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t sequence_number;

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s [--operation read-random|read-urandom|getrandom]\n"
		"          [--api raw|libc] [--mode normal|efault|invalid-fd|regular-file]\n"
		"          [--size N] [--threads N] [--iterations N] [--flags N]\n"
		"          [--start-delay-ms N] [--hold-ms N] [--output FILE|-]\n",
		program);
}

static int parse_u64(const char *raw, uint64_t maximum, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(raw, &end, 0);
	if (errno || end == raw || *end != '\0' || parsed > maximum)
		return -1;
	*value = (uint64_t)parsed;
	return 0;
}

static const char *operation_name(enum operation operation)
{
	return operation == OP_GETRANDOM ? "getrandom" : "read";
}

static const char *api_name(const struct options *options)
{
	return options->api == API_LIBC ? "libc" : "raw";
}

static const char *device_path(enum operation operation)
{
	return operation == OP_READ_RANDOM ? "/dev/random" : "/dev/urandom";
}

static void emit_record(const struct options *options, pid_t tid, int fd,
			const char *path, ssize_t result, int saved_errno,
			const unsigned char *buffer)
{
	size_t captured = result > 0 ? (size_t)result : 0;
	bool expected;
	uint64_t sequence;
	size_t index;

	if (captured > CAPTURE_LIMIT)
		captured = CAPTURE_LIMIT;
	expected = options->mode == MODE_NORMAL && result > 0;

	pthread_mutex_lock(&output_lock);
	sequence = ++sequence_number;
	fprintf(output,
		"{\"schema\":\"memento.syscall-ground-truth/v1\","
		"\"sequence\":%" PRIu64 ",\"pid\":%ld,\"tid\":%ld,"
		"\"operation\":\"%s\",\"api\":\"%s\",\"path\":\"%s\","
		"\"fd\":%d,\"requested_length\":%zu,\"returned_length\":%zd,"
		"\"captured_length\":%zu,\"flags\":%u,\"value_hex\":\"",
		sequence, (long)getpid(), (long)tid,
		operation_name(options->operation), api_name(options), path,
		fd, options->size, result, captured, options->flags);
	for (index = 0; index < captured; index++)
		fprintf(output, "%02x", buffer[index]);
	fprintf(output, "\",\"errno\":%d,\"expected_observed\":%s}\n",
		saved_errno, expected ? "true" : "false");
	fflush(output);
	pthread_mutex_unlock(&output_lock);
}

static int open_read_target(const struct options *options, const char **path)
{
	if (options->mode == MODE_INVALID_FD) {
		*path = device_path(options->operation);
		return -1;
	}
	if (options->mode == MODE_REGULAR_FILE)
		*path = options->regular_path;
	else
		*path = device_path(options->operation);
	return open(*path, O_RDONLY | O_CLOEXEC);
}

static int run_once(const struct options *options)
{
	unsigned char *buffer;
	const char *path = "";
	void *destination;
	ssize_t result;
	int fd = -1;
	int saved_errno;
	int expected_errno = 0;

	buffer = calloc(options->size ? options->size : 1, 1);
	if (buffer == NULL) {
		perror("calloc");
		return -1;
	}
	destination = options->mode == MODE_EFAULT ?
		(void *)(uintptr_t)1 : (void *)buffer;

	errno = 0;
	if (options->operation == OP_GETRANDOM) {
		if (options->api == API_LIBC)
			result = getrandom(destination, options->size, options->flags);
		else
			result = syscall(SYS_getrandom, destination, options->size,
					 options->flags);
	} else {
		fd = open_read_target(options, &path);
		if (fd < 0 && options->mode != MODE_INVALID_FD) {
			perror("open read target");
			free(buffer);
			return -1;
		}
		if (options->api == API_RAW)
			result = syscall(SYS_read, fd, destination, options->size);
		else
			result = read(fd, destination, options->size);
	}
	saved_errno = result < 0 ? errno : 0;

	if (options->mode == MODE_EFAULT)
		expected_errno = EFAULT;
	else if (options->mode == MODE_INVALID_FD)
		expected_errno = EBADF;

	emit_record(options, (pid_t)syscall(SYS_gettid), fd, path, result,
		    saved_errno, buffer);

	if (fd >= 0)
		close(fd);
	free(buffer);

	if (expected_errno != 0)
		return result == -1 && saved_errno == expected_errno ? 0 : -1;
	return result == (ssize_t)options->size ? 0 : -1;
}

static void *worker_main(void *opaque)
{
	struct worker *worker = opaque;
	unsigned int iteration;

	(void)worker->index;
	for (iteration = 0; iteration < worker->options->iterations; iteration++) {
		if (run_once(worker->options) != 0)
			worker->failures++;
	}
	return NULL;
}

static int create_regular_fixture(struct options *options)
{
	unsigned char *data;
	size_t index;
	ssize_t written;
	int fd;
	const char *basename;

	strcpy(options->regular_dir, "/tmp/memento-syscall-probe.XXXXXX");
	if (mkdtemp(options->regular_dir) == NULL)
		return -1;
	basename = options->operation == OP_READ_RANDOM ? "random" : "urandom";
	if (snprintf(options->regular_path, sizeof(options->regular_path),
		     "%s/%s", options->regular_dir, basename) >=
	    (int)sizeof(options->regular_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = open(options->regular_path,
		  O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	data = malloc(options->size ? options->size : 1);
	if (data == NULL) {
		close(fd);
		return -1;
	}
	for (index = 0; index < options->size; index++)
		data[index] = (unsigned char)(index & 0xffU);
	written = write(fd, data, options->size);
	free(data);
	if (close(fd) != 0 || written != (ssize_t)options->size)
		return -1;
	return 0;
}

static void remove_regular_fixture(const struct options *options)
{
	if (options->regular_path[0] != '\0')
		unlink(options->regular_path);
	if (options->regular_dir[0] != '\0')
		rmdir(options->regular_dir);
}

static void hold_process(unsigned int milliseconds)
{
	struct timespec duration;

	duration.tv_sec = milliseconds / 1000U;
	duration.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
	while (nanosleep(&duration, &duration) != 0 && errno == EINTR)
		;
}

int main(int argc, char **argv)
{
	struct options options = {
		.operation = OP_GETRANDOM,
		.api = API_RAW,
		.mode = MODE_NORMAL,
		.size = 32,
		.threads = 1,
		.iterations = 1,
		.output_path = "-",
	};
	pthread_t *threads = NULL;
	struct worker *workers = NULL;
	uint64_t parsed;
	unsigned int index;
	int option;
	int output_fd = -1;
	int failures = 0;

	static const struct option long_options[] = {
		{"operation", required_argument, NULL, 'o'},
		{"api", required_argument, NULL, 'a'},
		{"mode", required_argument, NULL, 'm'},
		{"size", required_argument, NULL, 's'},
		{"threads", required_argument, NULL, 't'},
		{"iterations", required_argument, NULL, 'i'},
		{"flags", required_argument, NULL, 'f'},
		{"start-delay-ms", required_argument, NULL, 'S'},
		{"hold-ms", required_argument, NULL, 'H'},
		{"output", required_argument, NULL, 'O'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	while ((option = getopt_long(argc, argv, "o:a:m:s:t:i:f:S:H:O:h",
				     long_options, NULL)) != -1) {
		switch (option) {
		case 'o':
			if (strcmp(optarg, "read-random") == 0)
				options.operation = OP_READ_RANDOM;
			else if (strcmp(optarg, "read-urandom") == 0)
				options.operation = OP_READ_URANDOM;
			else if (strcmp(optarg, "getrandom") == 0)
				options.operation = OP_GETRANDOM;
			else
				goto bad_usage;
			break;
		case 'a':
			if (strcmp(optarg, "raw") == 0)
				options.api = API_RAW;
			else if (strcmp(optarg, "libc") == 0)
				options.api = API_LIBC;
			else
				goto bad_usage;
			break;
		case 'm':
			if (strcmp(optarg, "normal") == 0)
				options.mode = MODE_NORMAL;
			else if (strcmp(optarg, "efault") == 0)
				options.mode = MODE_EFAULT;
			else if (strcmp(optarg, "invalid-fd") == 0)
				options.mode = MODE_INVALID_FD;
			else if (strcmp(optarg, "regular-file") == 0)
				options.mode = MODE_REGULAR_FILE;
			else
				goto bad_usage;
			break;
		case 's':
			if (parse_u64(optarg, MAX_REQUEST, &parsed) != 0)
				goto bad_usage;
			options.size = (size_t)parsed;
			break;
		case 't':
			if (parse_u64(optarg, MAX_THREADS, &parsed) != 0 ||
			    parsed == 0)
				goto bad_usage;
			options.threads = (unsigned int)parsed;
			break;
		case 'i':
			if (parse_u64(optarg, UINT_MAX, &parsed) != 0 ||
			    parsed == 0)
				goto bad_usage;
			options.iterations = (unsigned int)parsed;
			break;
		case 'f':
			if (parse_u64(optarg, UINT_MAX, &parsed) != 0)
				goto bad_usage;
			options.flags = (unsigned int)parsed;
			break;
		case 'S':
			if (parse_u64(optarg, UINT_MAX, &parsed) != 0)
				goto bad_usage;
			options.start_delay_ms = (unsigned int)parsed;
			break;
		case 'H':
			if (parse_u64(optarg, UINT_MAX, &parsed) != 0)
				goto bad_usage;
			options.hold_ms = (unsigned int)parsed;
			break;
		case 'O':
			options.output_path = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			goto bad_usage;
		}
	}
	if (optind != argc)
		goto bad_usage;
	if (options.operation == OP_GETRANDOM &&
	    (options.mode == MODE_INVALID_FD ||
	     options.mode == MODE_REGULAR_FILE))
		goto bad_usage;

	if (strcmp(options.output_path, "-") == 0) {
		output = stdout;
	} else {
		output_fd = open(options.output_path,
				 O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
		if (output_fd < 0) {
			perror("open output");
			return 1;
		}
		output = fdopen(output_fd, "w");
		if (output == NULL) {
			perror("fdopen output");
			close(output_fd);
			return 1;
		}
	}
	setvbuf(output, NULL, _IOLBF, 0);

	if (options.mode == MODE_REGULAR_FILE &&
	    create_regular_fixture(&options) != 0) {
		perror("create regular fixture");
		if (output != stdout)
			fclose(output);
		remove_regular_fixture(&options);
		return 1;
	}
	if (options.start_delay_ms != 0)
		hold_process(options.start_delay_ms);

	threads = calloc(options.threads, sizeof(*threads));
	workers = calloc(options.threads, sizeof(*workers));
	if (threads == NULL || workers == NULL) {
		perror("allocate workers");
		failures = 1;
		goto out;
	}
	for (index = 0; index < options.threads; index++) {
		workers[index].options = &options;
		workers[index].index = index;
		if (pthread_create(&threads[index], NULL, worker_main,
				   &workers[index]) != 0) {
			fprintf(stderr, "pthread_create failed at worker %u\n", index);
			options.threads = index;
			failures = 1;
			break;
		}
	}
	for (index = 0; index < options.threads; index++) {
		pthread_join(threads[index], NULL);
		failures += workers[index].failures;
	}
	if (options.hold_ms != 0)
		hold_process(options.hold_ms);

out:
	remove_regular_fixture(&options);
	free(threads);
	free(workers);
	if (output != stdout && fclose(output) != 0)
		failures++;
	return failures == 0 ? 0 : 1;

bad_usage:
	usage(argv[0]);
	return 2;
}

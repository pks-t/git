/*
Copyright 2020 Google LLC

Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file or at
https://developers.google.com/open-source/licenses/bsd
*/

#include "system.h"

#include "basics.h"
#include "blocksource.h"
#include "reftable-blocksource.h"
#include "reftable-error.h"

#if defined(NO_MMAP)
static int use_mmap = 0;
#else
static int use_mmap = 1;
#endif

static void strbuf_return_block(void *b, struct reftable_block *dest)
{
	if (dest->len)
		memset(dest->data, 0xff, dest->len);
	reftable_free(dest->data);
}

static void strbuf_close(void *b)
{
}

static int strbuf_read_block(void *v, struct reftable_block *dest, uint64_t off,
			     uint32_t size)
{
	struct strbuf *b = v;
	assert(off + size <= b->len);
	dest->data = reftable_calloc(size);
	memcpy(dest->data, b->buf + off, size);
	dest->len = size;
	return size;
}

static uint64_t strbuf_size(void *b)
{
	return ((struct strbuf *)b)->len;
}

static struct reftable_block_source_vtable strbuf_vtable = {
	.size = &strbuf_size,
	.read_block = &strbuf_read_block,
	.return_block = &strbuf_return_block,
	.close = &strbuf_close,
};

void block_source_from_strbuf(struct reftable_block_source *bs,
			      struct strbuf *buf)
{
	assert(!bs->ops);
	bs->ops = &strbuf_vtable;
	bs->arg = buf;
}

static void malloc_return_block(void *b, struct reftable_block *dest)
{
	if (dest->len)
		memset(dest->data, 0xff, dest->len);
	reftable_free(dest->data);
}

static struct reftable_block_source_vtable malloc_vtable = {
	.return_block = &malloc_return_block,
};

static struct reftable_block_source malloc_block_source_instance = {
	.ops = &malloc_vtable,
};

struct reftable_block_source malloc_block_source(void)
{
	return malloc_block_source_instance;
}

struct file_block_source {
	int fd;
	uint64_t size;
	unsigned char *data;
};

static uint64_t file_size(void *b)
{
	return ((struct file_block_source *)b)->size;
}

static void file_return_block(void *b, struct reftable_block *dest)
{
}

static void file_close(void *v)
{
	struct file_block_source *b = v;

	if (b->fd >= 0) {
		close(b->fd);
		b->fd = -1;
	}

	if (use_mmap)
		munmap(b->data, b->size);
	else
		reftable_free(b->data);
	b->data = NULL;

	reftable_free(b);
}

static int file_read_block(void *v, struct reftable_block *dest, uint64_t off,
			   uint32_t size)
{
	struct file_block_source *b = v;
	assert(off + size <= b->size);
	dest->data = b->data + off;
	dest->len = size;
	return size;
}

static struct reftable_block_source_vtable file_vtable = {
	.size = &file_size,
	.read_block = &file_read_block,
	.return_block = &file_return_block,
	.close = &file_close,
};

int reftable_block_source_from_file(struct reftable_block_source *bs,
				    const char *name)
{
	struct stat st = { 0 };
	int err = 0;
	int fd;
	struct file_block_source *p = NULL;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			return REFTABLE_NOT_EXIST_ERROR;
		}
		return -1;
	}

	err = fstat(fd, &st);
	if (err < 0) {
		close(fd);
		return REFTABLE_IO_ERROR;
	}

	p = reftable_calloc(sizeof(struct file_block_source));
	p->size = st.st_size;
	if (use_mmap) {
		p->data = xmmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		p->fd = fd;
	} else {
		p->data = xmalloc(st.st_size);
		if (read_in_full(fd, p->data, st.st_size) != st.st_size) {
			close(fd);
			return -1;
		}
		close(fd);
		p->fd = -1;
	}

	assert(!bs->ops);
	bs->ops = &file_vtable;
	bs->arg = p;
	return 0;
}

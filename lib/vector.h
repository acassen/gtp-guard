/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generic vector interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 */
#pragma once

/* vector definition */
typedef struct vector {
	unsigned int	active;
	unsigned int	allocated;
	void		**slot;
} vector_t;

/* Some defines */
#define VECTOR_DEFAULT_SIZE 1

/* Some usefull macros */
#define vector_slot(V,E) ((V)->slot[(E)])
#define vector_size(V)   ((V)->allocated)
#define vector_active(V) ((V)->active)
#define vector_foreach_slot(v,p,i) \
	for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]); i++)

/* Prototypes */
vector_t *vector_alloc(void);
vector_t *vector_init(unsigned int size);
void vector_alloc_slot(vector_t *v);
void vector_insert_slot(vector_t *v, int index, void *value);
vector_t *vector_copy(vector_t *v);
void vector_ensure(vector_t *v, unsigned int num);
int vector_empty_slot(vector_t *v);
int vector_set(vector_t *v, void *val);
void vector_set_slot(vector_t *v, void *val);
int vector_set_index(vector_t *v, unsigned int i, const void *val);
void *vector_lookup(vector_t *v, unsigned int i);
void *vector_lookup_ensure(vector_t *v, unsigned int i);
void vector_unset(vector_t *v, unsigned int i);
unsigned int vector_count(vector_t *v);
void vector_only_wrapper_free(vector_t *v);
void vector_only_index_free(void *slot);
void vector_only_slot_free(void *slot);
void vector_free(vector_t *v);
void vector_dump(vector_t *v);
void free_strvec(vector_t *v);
void dump_strvec(vector_t *v);

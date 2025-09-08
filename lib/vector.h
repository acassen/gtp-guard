/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generic vector interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 */
#pragma once

/* vector definition */
struct vector {
	unsigned int	active;
	unsigned int	allocated;
	void		**slot;
};

/* Some defines */
#define VECTOR_DEFAULT_SIZE 1

/* Some usefull macros */
#define vector_slot(V,E) ((V)->slot[(E)])
#define vector_size(V)   ((V)->allocated)
#define vector_active(V) ((V)->active)
#define vector_foreach_slot(v,p,i) \
	for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]); i++)

/* Prototypes */
struct vector *vector_alloc(void);
struct vector *vector_init(unsigned int size);
void vector_alloc_slot(struct vector *v);
void vector_insert_slot(struct vector *v, int index, void *value);
struct vector *vector_copy(struct vector *v);
void vector_ensure(struct vector *v, unsigned int num);
int vector_empty_slot(struct vector *v);
int vector_set(struct vector *v, void *val);
void vector_set_slot(struct vector *v, void *val);
int vector_set_index(struct vector *v, unsigned int i, const void *val);
void *vector_lookup(struct vector *v, unsigned int i);
void *vector_lookup_ensure(struct vector *v, unsigned int i);
void vector_unset(struct vector *v, unsigned int i);
unsigned int vector_count(struct vector *v);
void vector_only_wrapper_free(struct vector *v);
void vector_only_index_free(void *slot);
void vector_only_slot_free(void *slot);
void vector_free(struct vector *v);
void vector_dump(struct vector *v);
void free_strvec(struct vector *v);
void dump_strvec(struct vector *v);

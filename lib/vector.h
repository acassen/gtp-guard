/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generic vector interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _VECTOR_H
#define _VECTOR_H

/* vector definition */
typedef struct _vector {
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
extern vector_t *vector_alloc(void);
extern vector_t *vector_init(unsigned int);
extern void vector_alloc_slot(vector_t *);
extern void vector_insert_slot(vector_t *, int, void *);
extern vector_t *vector_copy(vector_t *);
extern void vector_ensure(vector_t *, unsigned int);
extern int vector_empty_slot(vector_t *);
extern int vector_set(vector_t *, void *);
extern void vector_set_slot(vector_t *, void *);
extern int vector_set_index(vector_t *, unsigned int, const void *);
extern void *vector_lookup(vector_t *, unsigned int);
extern void *vector_lookup_ensure(vector_t *, unsigned int);
extern void vector_unset(vector_t *, unsigned int);
extern unsigned int vector_count(vector_t *);
extern void vector_only_wrapper_free(vector_t *);
extern void vector_only_index_free(void *);
extern void vector_only_slot_free(void *);
extern void vector_free(vector_t *);
extern void vector_dump(vector_t *);
extern void free_strvec(vector_t *);
extern void dump_strvec(vector_t *);

#endif

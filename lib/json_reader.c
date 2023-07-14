/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "memory.h"
#include "json_reader.h"

#define WHITE_SPACE_STR " \t\f\n\r\v"
const char *WHITE_SPACE = WHITE_SPACE_STR;


/*
 *	JSON handling Matrix
 */
static bool json_parse_null(const char **, json_node_t **);
static bool json_parse_false(const char **, json_node_t **);
static bool json_parse_true(const char **, json_node_t **);
static bool json_parse_string(const char **, json_node_t **);
static bool json_parse_array(const char **, json_node_t **);
static bool json_parse_object(const char **, json_node_t **);
static bool json_parse_number(const char **, json_node_t **);

static void json_dump_null(json_node_t *, int);
static void json_dump_bool(json_node_t *, int);
static void json_dump_string(json_node_t *, int);
static void json_dump_number(json_node_t *, int);
static void json_dump_array(json_node_t *, int);
static void json_dump_object(json_node_t *, int);
static void json_dump_dummy(json_node_t *, int);
static void json_dump_tab(int);

#define JSON_PARSE_TBL_SIZE 6
static struct {
	char	type;
	bool	(*parse) (const char **, json_node_t **);
	void	(*dump) (json_node_t *, int);
} json_parse_table[JSON_PARSE_TBL_SIZE + 1] = {
	{	'n', 	json_parse_null,	json_dump_null		},
	{	'f', 	json_parse_false,	json_dump_bool		},
	{	't', 	json_parse_true,	json_dump_string	},
	{	'"', 	json_parse_string,	json_dump_number	},
	{	'[', 	json_parse_array,	json_dump_array		},
	{	'{', 	json_parse_object,	json_dump_object	},
	{	'?', 	json_parse_number,	json_dump_dummy		}
};


/*
 *	Node creation
 */
static void
json_node_append(json_node_t *parent, json_node_t *child)
{
	child->parent = parent;
	child->prev = parent->child.tail;
	child->next = NULL;

	if (parent->child.tail != NULL)
		parent->child.tail->next = child;
	else
		parent->child.head = child;
	parent->child.tail = child;
}

static void
json_append(json_node_t *obj, char *key, json_node_t *value)
{
	value->key = key;
	json_node_append(obj, value);
}

void
json_destroy(json_node_t *node)
{
	json_node_t *n, *tmp;

	if (!node)
		return;

	FREE_PTR(node->key);

	if (node->tag == JSON_STRING) {
		FREE_PTR(node->str_value);
		goto end;
	}

	if (node->tag == JSON_OBJECT || node->tag == JSON_ARRAY) {
//		json_for_each_node_safe(n, tmp, node) {
		for (n = node->child.head; n; n = tmp) {
			tmp = n->next;
			json_destroy(n);
		}
	}

  end:
	FREE(node);
}

static json_node_t *
json_mknode(json_tag_t tag)
{
	json_node_t *node;

	node = (json_node_t *) MALLOC(sizeof(json_node_t));
	if (!node)
		return NULL;
	node->tag = tag;

	return node;
}

json_node_t *
json_mknull(void)
{
	return json_mknode(JSON_NULL);
}

json_node_t *
json_mkbool(bool b)
{
	json_node_t *node = json_mknode(JSON_BOOL);
	if (!node)
		return NULL;
	node->bool_value = b;
	return node;
}

json_node_t *
json_mkstring(char *str)
{
	json_node_t *node = json_mknode(JSON_STRING);
	if (!node)
		return NULL;
	node->str_value = str;
	return node;
}

json_node_t *
json_mknumber(double n)
{
	json_node_t *node = json_mknode(JSON_NUMBER);
	if (!node)
		return NULL;
	node->number_value = n;	
	return node;
}

json_node_t *
json_mkarray(void)
{
	return json_mknode(JSON_ARRAY);
}

json_node_t *
json_mkobject(void)
{
	return json_mknode(JSON_OBJECT);
}



/*
 *	Parser
 */
static bool json_parse_value(const char **, json_node_t **);

static void
json_parser_skip_space(const char **sp)
{
	const char *s = *sp;

	*sp += strspn(s, WHITE_SPACE);
}

static bool
json_exact_match(const char **sp, char *str)
{
	const char *s = *sp;

	for (; *str != '\0'; s++, str++) {
		if (*s != *str) {
			return false;
		}
	}

	*sp = s;
	return true;
}

static bool
json_extract_string(const char **sp, char **out)
{
	const char *s = *sp;
	const char *start, *cp;
	size_t str_len;
	char *str;

	if (*s++ != '"')
		return false;

	start = s;
	if (!(cp = strchr(start, '"')))
		return false;

	str_len = (size_t) (cp - start);
	str = MALLOC(str_len + 1);
	memcpy(str, start, str_len);
	*out = str;
	*sp = s + str_len + 1;
	return true;
}

static bool
json_extract_number(const char **sp, double *out)
{
	const char *s = *sp;

	/* '-'? */
	if (*s == '-')
		s++;

	/* (0 | [1-9][0-9]*) */
	if (*s == '0') {
		s++;
	} else {
		if (!isdigit((int) *s))
			return false;
		do {    
			s++;
		} while (isdigit((int) *s));
	}

	/* ('.' [0-9]+)? */
	if (*s == '.') {
		s++;
		if (!isdigit((int) *s))
			return false;
		do {
			s++;
		} while (isdigit((int) *s));
	}

	*out = strtod(*sp, NULL);
	*sp = s;
	return true;
}


static bool
json_parse_null(const char **sp, json_node_t **out)
{
	const char *s = *sp;

	if (!json_exact_match(&s, "null"))
		return false;

	*out = json_mknull();
	*sp = s;
	return true;
}

static bool
json_parse_false(const char **sp, json_node_t **out)
{
	const char *s = *sp;

	if (!json_exact_match(&s, "false"))
		return false;

	*out = json_mkbool(false);
	*sp = s;
	return true;
}

static bool
json_parse_true(const char **sp, json_node_t **out)
{
	const char *s = *sp;

	if (!json_exact_match(&s, "true"))
		return false;

	*out = json_mkbool(true);
	*sp = s;
	return true;
}

static bool
json_parse_string(const char **sp, json_node_t **out)
{
	const char *s = *sp;
	char *str;

	if (!json_extract_string(&s, &str))
		return false;

	*out = json_mkstring(str);
	*sp = s;
	return true;
}

static bool
json_parse_array(const char **sp, json_node_t **out)
{
	const char *s = *sp;
	json_node_t *array = NULL, *element;

	if (*s++ != '[')
		goto error;

	json_parser_skip_space(&s);

	if (*s == ']') {
		s++;
		goto end;
	}

	array = json_mkarray();
	if (!array)
		goto error;

	while (true) {
		if (!json_parse_value(&s, &element))
			goto error;

		json_append(array, NULL, element);

		if (*s == ']') {
			s++;
			break;
		}

		if (*s++ != ',')
			goto error;
		json_parser_skip_space(&s);
	}

  end:
	*sp = s;
	*out = array;
	return true;
  error:
	json_destroy(array);
	return false;
}

static bool
json_parse_object(const char **sp, json_node_t **out)
{
	const char *s = *sp;
	json_node_t *obj = NULL, *value;
	char *key;

	if (*s++ != '{')
		goto error;

	json_parser_skip_space(&s);

	if (*s == '}') {
		s++;
		goto end;
	}


	obj = json_mkobject();
	if (!obj)
		return false;

	while (true) {
		if (!json_extract_string(&s, &key))
			goto error;

		json_parser_skip_space(&s);
		if (*s++ != ':')
			goto error_free;

		if (!json_parse_value(&s, &value))
			goto error_free;

		json_append(obj, key, value);

		if (*s == '}') {
			s++;
			break;
		}

		if (*s++ != ',')
			goto error;
		json_parser_skip_space(&s);
	}

  end:
	*sp = s;
	*out = obj;
	return true;

  error_free:
	FREE(key);
  error:
	json_destroy(obj);
	return false;
}

static bool
json_parse_number(const char **sp, json_node_t **out)
{
	const char *s = *sp;
	double number;

	if (!json_extract_number(&s, &number))
		return false;

	*out = json_mknumber(number);
	*sp = s;
	return true;
}


static bool
json_parse_value(const char **sp, json_node_t **out)
{
	const char *s = *sp;
	int i;

	json_parser_skip_space(&s);

	for (i = 0; i < JSON_PARSE_TBL_SIZE; i++) {
		if (*s == json_parse_table[i].type) {
			if (!(*json_parse_table[i].parse) (&s, out)) {
				return false;
			}
			goto end;
		}
	}

	/* Default to parse number */
	if ((*json_parse_table[i].parse) (&s, out))
		goto end;

	return false;

  end:
	json_parser_skip_space(&s);
	*sp = s;
	return true;
}


json_node_t *
json_decode(const char *str)
{
	const char *s = str;
	json_node_t *node;

	if (!json_parse_value(&s, &node))
		return NULL;

	/* Partial parsing */
	if (*s != 0) {
		json_destroy(node);
		return NULL;
	}

	return node;
}


/*
 *	Dump
 */
static void
json_dump_level(json_node_t *node, int level)
{
	json_node_t *n;

	if (!node)
		return;

	json_for_each_node(n, node) {
		(*json_parse_table[n->tag].dump) (n, level + 1);
		if (n->next)
			printf(",\n");
	}
}

void
json_dump(json_node_t *node)
{
	(*json_parse_table[node->tag].dump) (node, 0);
}

static void json_dump_tab(int level)
{
	int i;
	for (i = 0; i < level; i++)
		putchar(' ');
}

static void json_dump_null(json_node_t *node, int level)
{
	json_dump_tab(level);
	if (node->key)
		printf("\"%s\":", node->key);
	printf("null");
}

static void json_dump_bool(json_node_t *node, int level)
{
	json_dump_tab(level);
	if (node->key)
		printf("\"%s\":", node->key);
	printf("%s", node->bool_value ? "true" : "false");

}

static void json_dump_string(json_node_t *node, int level)
{
	json_dump_tab(level);
	if (node->key)
		printf("\"%s\":", node->key);
	printf("\"%s\"", node->str_value);
}

static void json_dump_number(json_node_t *node, int level)
{
	json_dump_tab(level);
	if (node->key)
		printf("\"%s\":", node->key);
	printf("%f", node->number_value);
}

static void json_dump_array(json_node_t *node, int level)
{
	json_dump_tab(level);
	printf("[\n");
	json_dump_level(node, level);
	printf("]\n");
}

static void json_dump_object(json_node_t *node, int level)
{
	json_dump_tab(level);
	if (node->key)
		printf("\"%s\":", node->key);
	printf("{\n");
	json_dump_level(node, level);
	printf("}\n");
}

static void json_dump_dummy(json_node_t *node, int level)
{
}


/*
 *	Lookup
 */
json_node_t *
json_find_member(json_node_t *node, const char *name)
{
	json_node_t *n;

	if (!node || node->tag != JSON_OBJECT)
		return NULL;

	json_for_each_node(n, node) {
		if (!strcmp(n->key, name))
			return n;
	}

	return NULL;
}

json_node_t *
json_find_member_boolvalue(json_node_t *node, const char *name, bool *value)
{
	json_node_t *n;

	n = json_find_member(node, name);
	if (!n)
		return NULL;

	if (n->tag == JSON_BOOL) {
		*value = n->bool_value;
		return n;
	}

	return NULL;
}

json_node_t *
json_find_member_strvalue(json_node_t *node, const char *name, char **value)
{
	json_node_t *n;

	n = json_find_member(node, name);
	if (!n)
		return NULL;

	if (n->tag == JSON_STRING) {
		*value = n->str_value;
		return n;
	}

	return NULL;
}

json_node_t *
json_find_member_numbervalue(json_node_t *node, const char *name, double *value)
{
	json_node_t *n;

	n = json_find_member(node, name);
	if (!n)
		return NULL;

	if (n->tag == JSON_NUMBER) {
		*value = n->number_value;
		return n;
	}

	return NULL;
}

json_node_t *
json_find_member_doublevalue(json_node_t *node, const char *name, double *value)
{
	return json_find_member_numbervalue(node, name, value);
}
	
json_node_t *
json_find_member_intvalue(json_node_t *node, const char *name, int *value)
{
	json_node_t *n;

	n = json_find_member(node, name);
	if (!n)
		return NULL;

	if (n->tag == JSON_NUMBER) {
		*value = (int) n->number_value;
		return n;
	}

	return NULL;
}

json_node_t *
json_first_child(const json_node_t *node)
{
	if (node && (node->tag == JSON_ARRAY || node->tag == JSON_OBJECT))
		return node->child.head;

	return NULL;
}

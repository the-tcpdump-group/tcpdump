/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <dlfcn.h>

extern int profile_func_level;
int profile_func_level = -1;

/*
 * Generate instrumentation calls for entry and exit to functions.
 * Just after function entry and just before function exit, the
 * following profiling functions are called with the address of the
 * current function and its call site (currently not use).
 *
 * The attribute 'no_instrument_function' causes this instrumentation is
 * not done.
 *
 * These profiling functions print the function names with indentation
 * and call level.
 *
 * To instument a static function, remove temporarily the static specifier.
 */

#ifndef ND_NO_INSTRUMENT
#define ND_NO_INSTRUMENT __attribute__((no_instrument_function))
#endif

void __cyg_profile_func_enter(void *this_fn, void *call_site) ND_NO_INSTRUMENT;

void __cyg_profile_func_exit(void *this_fn, void *call_site) ND_NO_INSTRUMENT;

/*
 * Structure table to store the functions data from FILE_NAME.
 * FILE_NAME is generated via:
 * $ nm $(PROG) | grep ' [tT] '
 * or
 * $ nm $(PROG) | grep ' [T] '
 */

#define MAX_FUNCTIONS 20000
static struct {
	void *addr;
	char type;
	char name[128];
} functions[MAX_FUNCTIONS] ;
static int functions_count;
static int initialization_done;

/*
 * Read the result of nm in functions[]
 */

#define FILE_NAME "tcpdump_instrument_functions.nm"

void read_functions_table(void) ND_NO_INSTRUMENT;

void
read_functions_table(void)
{
	FILE *fp;
	int i = 0;
	if ((fp = fopen(FILE_NAME, "r")) == NULL) {
	printf("Warning: Cannot open \"%s\" file\n", FILE_NAME);
		return;
	}
	while (i < MAX_FUNCTIONS && fscanf(fp, "%p %c %s", &functions[i].addr,
		      &functions[i].type, functions[i].name) != EOF)

		i++;
	fclose(fp);
	functions_count = i;
}

/*
 * Get the function name by searching in functions[]
 */

static const char * get_function_name(void *func) ND_NO_INSTRUMENT;

static const char *
get_function_name(void *func)
{
	int i = 0;
	int found = 0;
	if (!initialization_done) {
		read_functions_table();
		initialization_done = 1;
	}
	while (i < functions_count) {
		if (functions[i].addr == func) {
			found = 1;
			break;
		}
		i++;
	}
	if (found)
		return (functions[i].name);
	else
		return NULL;
}

void
__cyg_profile_func_enter(void *this_fn,
			      void *call_site __attribute__((unused)))
{
	int i;
	const char *function_name;

	if ((function_name = get_function_name(this_fn)) != NULL) {
		profile_func_level += 1;
		for (i = 0 ; i < profile_func_level ; i++)
			putchar(' ');
		printf("[>> %s (%d)]\n", function_name, profile_func_level);
	}
	fflush(stdout);
}

void
__cyg_profile_func_exit(void *this_fn,
			     void *call_site __attribute__((unused)))
{
	int i;
	const char *function_name;

	if ((function_name = get_function_name(this_fn)) != NULL) {
		for (i = 0 ; i < profile_func_level ; i++)
			putchar(' ');
		printf ("[<< %s (%d)]\n", function_name, profile_func_level);
		profile_func_level -= 1;
	}
	fflush(stdout);
}

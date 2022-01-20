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

void __cyg_profile_func_enter(void *this_fn, void *call_site)
			      __attribute__((no_instrument_function));

void __cyg_profile_func_exit(void *this_fn, void *call_site)
			     __attribute__((no_instrument_function));

/*
 * The get_function_name() get the function name by calling dladdr()
 */

static const char *get_function_name(void *func)
			      __attribute__((no_instrument_function));

static const char *
get_function_name(void *func)
{
	Dl_info info;
	const char *function_name;

	if (dladdr(func, &info))
		function_name = info.dli_sname;
	else
		function_name = NULL;
	return function_name;
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

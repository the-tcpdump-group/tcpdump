/*
 * wcwidth() implementation for Windows
 * Based on Markus Kuhn's public domain implementation
 */

#ifndef WCWIDTH_H
#define WCWIDTH_H

#include <wchar.h>

/* Determine the column width of a wide character */
int wcwidth(wchar_t ucs);

#endif /* WCWIDTH_H */

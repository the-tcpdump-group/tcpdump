/* @(#) $Header: /tcpdump/master/tcpdump/lbl/Attic/gnuc.h,v 1.4 2000-07-10 04:29:27 assar Exp $ (LBL) */

/* Define __P() macro, if necessary */
#ifndef __P
#if __STDC__
#define __P(protos) protos
#else
#define __P(protos) ()
#endif
#endif

/*
 * Handle new and old "dead" routine prototypes
 *
 * For example:
 *
 *	__dead void foo(void) __attribute__((volatile));
 *
 */
#ifdef __GNUC__
#ifndef __dead
#define __dead volatile
#endif
#else
#ifndef __dead
#define __dead
#endif
#endif

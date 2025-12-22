/*
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *	from: @(#)auth.h 1.17 88/02/08 SMI
 *	from: @(#)auth.h	2.3 88/08/07 4.0 RPCSRC
 * $FreeBSD: src/include/rpc/auth.h,v 1.14.2.1 1999/08/29 14:39:02 peter Exp $
 */

/*
 * auth.h, Authentication interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The data structures are completely opaque to the client.  The client
 * is required to pass a AUTH * to routines that create rpc
 * "sessions".
 */

/*
 * Status returned from authentication check
 */
enum sunrpc_auth_stat {
	SUNRPC_AUTH_OK=0,
	/*
	 * failed at remote end
	 */
	SUNRPC_AUTH_BADCRED=1,		/* bogus credentials (seal broken) */
	SUNRPC_AUTH_REJECTEDCRED=2,	/* client should begin new session */
	SUNRPC_AUTH_BADVERF=3,		/* bogus verifier (seal broken) */
	SUNRPC_AUTH_REJECTEDVERF=4,	/* verifier expired or was replayed */
	SUNRPC_AUTH_TOOWEAK=5,		/* rejected due to security reasons */
	/*
	 * failed locally
	*/
	SUNRPC_AUTH_INVALIDRESP=6,	/* bogus response verifier */
	SUNRPC_AUTH_FAILED=7		/* some unknown reason */
};

/*
 * Authentication info.  Opaque to client.
 */
struct sunrpc_opaque_auth {
	nd_uint32_t oa_flavor;		/* flavor of auth */
	nd_uint32_t oa_len;		/* length of opaque body */
	/* zero or more bytes of body */
};

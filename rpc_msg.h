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
 *	from: @(#)rpc_msg.h 1.7 86/07/16 SMI
 *	from: @(#)rpc_msg.h	2.1 88/07/29 4.0 RPCSRC
 * $FreeBSD: src/include/rpc/rpc_msg.h,v 1.11.2.1 1999/08/29 14:39:07 peter Exp $
 */

/*
 * rpc_msg.h
 * rpc message definition
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#define SUNRPC_MSG_VERSION	((uint32_t) 2)

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall struct but
 * different parts of unions within it.
 */

enum sunrpc_msg_type {
	SUNRPC_CALL=0,
	SUNRPC_REPLY=1
};

enum sunrpc_reply_stat {
	SUNRPC_MSG_ACCEPTED=0,
	SUNRPC_MSG_DENIED=1
};

enum sunrpc_accept_stat {
	SUNRPC_SUCCESS=0,
	SUNRPC_PROG_UNAVAIL=1,
	SUNRPC_PROG_MISMATCH=2,
	SUNRPC_PROC_UNAVAIL=3,
	SUNRPC_GARBAGE_ARGS=4,
	SUNRPC_SYSTEM_ERR=5
};

enum sunrpc_reject_stat {
	SUNRPC_RPC_MISMATCH=0,
	SUNRPC_AUTH_ERROR=1
};

/*
 * Reply part of an rpc exchange
 */

/*
 * Reply to an rpc request that was rejected by the server.
 */
struct sunrpc_rejected_reply {
	nd_uint32_t		 rj_stat;	/* enum reject_stat */
	union {
		struct {
			nd_uint32_t low;
			nd_uint32_t high;
		} RJ_versions;
		nd_uint32_t RJ_why;  /* enum auth_stat - why authentication did not work */
	} ru;
#define	rj_vers	ru.RJ_versions
#define	rj_why	ru.RJ_why
};

/*
 * Body of a reply to an rpc request.
 */
struct sunrpc_reply_body {
	nd_uint32_t	rp_stat;		/* enum reply_stat */
	struct sunrpc_rejected_reply rp_reject;	/* if rejected */
};

/*
 * Body of an rpc request call.
 */
struct sunrpc_call_body {
	nd_uint32_t cb_rpcvers;	/* must be equal to two */
	nd_uint32_t cb_prog;
	nd_uint32_t cb_vers;
	nd_uint32_t cb_proc;
	struct sunrpc_opaque_auth cb_cred;
	/* followed by opaque verifier */
};

/*
 * The rpc message
 */
struct sunrpc_msg {
	nd_uint32_t		rm_xid;
	nd_uint32_t		rm_direction;	/* enum msg_type */
	union {
		struct sunrpc_call_body RM_cmb;
		struct sunrpc_reply_body RM_rmb;
	} ru;
#define	rm_call		ru.RM_cmb
#define	rm_reply	ru.RM_rmb
};
#define	acpted_rply	ru.RM_rmb.ru.RP_ar
#define	rjcted_rply	ru.RM_rmb.ru.RP_dr

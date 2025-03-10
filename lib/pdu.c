/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef PS2_EE
#include "ps2_compat.h"
#endif

#ifdef PS3_PPU
#include "ps3_compat.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if defined(HAVE_SYS_UIO_H) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/uio.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include "slist.h"
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#ifdef HAVE_LIBKRB5
#include "krb5-wrapper.h"
#endif

void rpc_reset_queue(struct rpc_queue *q)
{
	q->head = NULL;
	q->tail = NULL;
	q->tailp = NULL;
}

/*
 * Push to the tail end of the queue
 */
void rpc_enqueue(struct rpc_queue *q, struct rpc_pdu *pdu)
{
	if (q->head == NULL) {
	        assert(q->tail == NULL);
		q->head = pdu;
        } else {
                assert(pdu != q->head);
                assert(pdu != q->tail);
		q->tail->next = pdu;
        }
	q->tail = pdu;
	pdu->next = NULL;
}

/**
 * Add pdu to the head of outqueue.
 * It tries to add pdu to the head but if the pdu at the head is partially
 * written to the socket it adds pdu after that.
 * We do that to not mix data from different pdus being sent on the socket.
 */
void rpc_add_to_outqueue_head(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        if (rpc->outqueue.head == NULL) {
                assert(rpc->outqueue.tail == NULL);
                assert(rpc->outqueue.tailp == NULL);
                assert(rpc->stats.outqueue_len == 0);

                rpc->outqueue.head = rpc->outqueue.tail = pdu;
                if (pdu->is_high_prio)
                        rpc->outqueue.tailp = pdu;
                pdu->next = NULL;
        } else {
                if (rpc->outqueue.head == rpc->outqueue.tail) {
                        assert(rpc->stats.outqueue_len == 1);
                        assert(rpc->outqueue.head->next == NULL);
                        assert(rpc->outqueue.tail->next == NULL);
                        assert(!rpc->outqueue.tailp ||
                                        (rpc->outqueue.tailp == rpc->outqueue.tail));
                        assert(pdu != rpc->outqueue.head);
                } else {
                        assert(rpc->stats.outqueue_len > 1);
                        assert(rpc->outqueue.head->next != NULL);
                        assert(rpc->outqueue.tail->next == NULL);
                        assert(pdu != rpc->outqueue.head);
                        assert(pdu != rpc->outqueue.tail);
                        assert(pdu != rpc->outqueue.tailp);
                }

                /*
                 * Add to the head if head pdu is not partially-sent, else add
                 * after that.
                 * If no high prio pdu queued and this one is high prio pdu,
                 * set tailp as well, also if added after head pdu and tailp
                 * points at head and pdu is high prio update tailp.
                 */
                if (rpc->outqueue.head->out.num_done == 0) {
                        pdu->next = rpc->outqueue.head;
                        rpc->outqueue.head = pdu;
                        if (pdu->is_high_prio && (rpc->outqueue.tailp == NULL))
                                rpc->outqueue.tailp = pdu;
                } else {
                        if (pdu->is_high_prio &&
                            ((rpc->outqueue.tailp == NULL) ||
                             (rpc->outqueue.tailp == rpc->outqueue.head)))
                                rpc->outqueue.tailp = pdu;
                        pdu->next = rpc->outqueue.head->next;
                        rpc->outqueue.head->next = pdu;
                }

                if (pdu->next == NULL)
                        rpc->outqueue.tail = pdu;
        }

        assert(rpc->outqueue.tail->next == NULL);
        assert(rpc->outqueue.tail->is_high_prio ==
                (rpc->outqueue.tailp == rpc->outqueue.tail));

        if (rpc->stats.outqueue_len++ == 0) {
                /*
                 * If this is the first pdu added to an empty outqueue let the
                 * service thread know.
                 */
                uint64_t evwrite = 1;
                [[maybe_unused]] ssize_t evbytes =
                        write(rpc_get_evfd(rpc), &evwrite, sizeof(evwrite));
                assert(evbytes == 8);
        }
}

/**
 * Head priority pdu is a high prio pdu added to outqueue.head, ahead of all
 * high (and low) prio pdus.
 */
void rpc_add_to_outqueue_headp(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        /*
         * AZAUTH RPC is the only one queued with head priority and
         * AZAUTH RPC MUST only be sent if use_azauth is true.
         */
        assert(rpc->use_azauth);

        /*
         * When rpc_add_to_outqueue_headp() is called there shouldn't be any
         * partially sent pdu in the queue. It's typically called either when
         * the connection is freshly created, at which time there are no pdus
         * in outqueue, or on reconnect, at which time outqueue must have been
         * reset and num_done must have been set to 0 for the head pdu.
         */
        if (rpc->outqueue.head != NULL) {
                assert(rpc->outqueue.head->out.num_done == 0);
        }

        pdu->is_head_prio = TRUE;
        pdu->is_high_prio = TRUE;
        rpc_add_to_outqueue_head(rpc, pdu);

        assert(rpc->outqueue.head != NULL);
        assert(rpc->outqueue.tail != NULL);
        assert(rpc->outqueue.tailp != NULL);
}

/**
 * High priority pdus are added after tailp.
 */
void rpc_add_to_outqueue_highp(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        assert(pdu->is_head_prio == FALSE);
        pdu->is_high_prio = TRUE;
        if (rpc->outqueue.tailp == NULL) {
                /*
                 * First high priority pdu, add to head.
                 */
                rpc_add_to_outqueue_head(rpc, pdu);
                assert(rpc->outqueue.head != NULL);
                assert(rpc->outqueue.tail != NULL);
                assert(rpc->outqueue.tailp != NULL);
        } else {
                assert(rpc->outqueue.head != NULL);
                assert(rpc->outqueue.tail != NULL);
                assert(pdu != rpc->outqueue.head);
                assert(pdu != rpc->outqueue.tail);
                assert(pdu != rpc->outqueue.tailp);
                assert(rpc->stats.outqueue_len > 0);

                pdu->next = rpc->outqueue.tailp->next;
                rpc->outqueue.tailp->next = pdu;
                if (rpc->outqueue.tail == rpc->outqueue.tailp)
                        rpc->outqueue.tail = pdu;
                rpc->outqueue.tailp = pdu;
                rpc->stats.outqueue_len++;
        }
}

/**
 * Low priority pdus are added to the tail.
 */
void rpc_add_to_outqueue_lowp(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        assert(pdu->is_head_prio == FALSE);
        pdu->is_high_prio = FALSE;
        rpc_enqueue(&rpc->outqueue, pdu);
        if (rpc->stats.outqueue_len++ == 0) {
                /*
                 * If this is the first pdu added to an empty outqueue let the
                 * service thread know.
                 */
                uint64_t evwrite = 1;
                [[maybe_unused]] ssize_t evbytes =
                        write(rpc_get_evfd(rpc), &evwrite, sizeof(evwrite));
                assert(evbytes == 8);
        }

        assert(rpc->outqueue.head != NULL);
        assert(rpc->outqueue.tail != NULL);
        assert(pdu->next == NULL);
}

/*
 * Return pdu to outqueue to be retransmitted.
 * It adds the pdu to the head of outqueue, unless the head pdu is partially
 * sent, in which case it adds it right after the head pdu.
 */
void rpc_return_to_outqueue(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        rpc_add_to_outqueue_head(rpc, pdu);

        /*
         * Only already transmitted PDUs are added back to outqueue, so sending
         * it out will entail a retransmit.
         */
        INC_STATS(rpc, num_retransmitted);
        pdu->is_retransmitted = 1;

        /*
         * Reset output and input cursors as we have to re-send the whole pdu
         * again (and read back the response fresh into pdu->in).
         */
        pdu->out.num_done = 0;
        rpc_reset_cursor(rpc, &pdu->in);
}

/*
 * Remove pdu from q.
 * If found it'll remove the pdu and update q->head and q->tail correctly.
 * Returns 0 if remove_pdu not found in q else returns 1.
 */
int rpc_remove_pdu_from_queue(struct rpc_queue *q, struct rpc_pdu *remove_pdu)
{
        if (q->head != NULL) {
                struct rpc_pdu *pdu = q->head;

                assert(q->tail != NULL);

                /*
                 * remove_pdu is the head pdu.
                 * Change the head to point to the next pdu.
                 * If tail is also pointing to remove_pdu, this means it's the
                 * only PDU and after removing that we will have an empty list.
                 * If tailp is pointing to remove_pdu, this means it's the
                 * only high prio pdu and after removing it tailp will be NULL.
                 */
                if (q->head == remove_pdu) {
                        q->head = remove_pdu->next;

                        if (q->tailp == remove_pdu) {
                                q->tailp = NULL;
                        }

                        if (q->tail == remove_pdu) {
                                assert(remove_pdu->next == NULL);
                                q->tail = NULL;
                                assert(q->tailp == NULL);
                                assert(q->head == NULL);
                        } else {
                                assert(q->head != NULL);
                        }

                        remove_pdu->next = NULL;
                        return 1;
                }

                /*
                 * remove_pdu is not the head pdu.
                 * Search for it and if found, remove it, and update tail if
                 * tail is pointing to remove_pdu.
                 */
                while (pdu->next && pdu->next != remove_pdu) {
                        pdu = pdu->next;
                }

                if (pdu->next == NULL) {
                        /* remove_pdu not found in q */
                        return 0;
                }

                pdu->next = remove_pdu->next;

                if (q->tail == remove_pdu) {
                        q->tail = pdu;
                }

                if (q->tailp == remove_pdu) {
                        assert(remove_pdu->is_high_prio);
                        if (pdu->is_high_prio)
                                q->tailp = pdu;
                        else
                                q->tailp = NULL;
                }

                remove_pdu->next = NULL;

                return 1;
        } else {
                assert(q->tail == NULL);
                assert(q->tailp == NULL);
                /* not found */
                return 0;
        }
}

unsigned int rpc_hash_xid(struct rpc_context *rpc, uint32_t xid)
{
	return (xid * 7919) % rpc->num_hashes;
}

#define PAD_TO_8_BYTES(x) ((x + 0x07) & ~0x07)

static struct rpc_pdu *rpc_allocate_reply_pdu(struct rpc_context *rpc,
                                              struct rpc_msg *res,
                                              size_t alloc_hint)
{
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	pdu = malloc(sizeof(struct rpc_pdu) + ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure and encode buffer");
		return NULL;
	}
	memset(pdu, 0, sizeof(struct rpc_pdu));
        pdu->flags              = PDU_DISCARD_AFTER_SENDING;
	pdu->xid                = 0;
	pdu->cb                 = NULL;
	pdu->private_data       = NULL;
	pdu->zdr_decode_fn      = NULL;
	pdu->zdr_decode_bufsize = 0;

	pdu->outdata.data = (char *)(pdu + 1);

        /* Add an iovector for the record marker. Ignored for UDP */
        rpc_add_iovector(rpc, &pdu->out, pdu->outdata.data, 4, NULL);

	zdrmem_create(&pdu->zdr, &pdu->outdata.data[4],
                      ZDR_ENCODEBUF_MINSIZE + alloc_hint, ZDR_ENCODE);

	if (zdr_replymsg(rpc, &pdu->zdr, res) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed with %s",
			      rpc_get_error(rpc));
		zdr_destroy(&pdu->zdr);
		free(pdu);
		return NULL;
	}

        /* Add an iovector for the header */
        rpc_add_iovector(rpc, &pdu->out, &pdu->outdata.data[4],
                         zdr_getpos(&pdu->zdr), NULL);

	return pdu;
}

struct rpc_pdu *rpc_allocate_pdu2(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize, size_t alloc_hint, int iovcnt_hint)
{
	struct rpc_pdu *pdu;
	struct rpc_msg msg;
	int pdu_size;
#ifdef HAVE_LIBKRB5
        uint32_t val;
#endif

#ifdef HAVE_TLS
	/*
	 * Caller overloads procedure to convey they want to send AUTH_TLS instead of
	 * AUTH_NONE for the NULL RPC.
	 */
	const bool_t send_auth_tls = !!(procedure & 0x80000000U);
	procedure = (procedure & 0x7FFFFFFFU);

	/* AUTH_TLS can only be sent for NFS NULL RPC */
	assert(!send_auth_tls || (program == NFS_PROGRAM && procedure == 0));
#endif /* HAVE_TLS */

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Since we already know how much buffer we need for the decoding
	 * we can just piggyback in the same alloc as for the pdu.
	 */
	pdu_size = PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	pdu_size += PAD_TO_8_BYTES(zdr_decode_bufsize);

	pdu = malloc(pdu_size + ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure and encode buffer");
		return NULL;
	}
	memset(pdu, 0, pdu_size);

#ifdef ENABLE_PARANOID
        /* PDU is not present in any queue to start with */
        pdu->in_outqueue = pdu->in_waitpdu = PDU_ABSENT;
#endif

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	pdu->xid                = rpc->xid++;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	pdu->cb                 = cb;
	pdu->private_data       = private_data;
	pdu->zdr_decode_fn      = zdr_decode_fn;
	pdu->zdr_decode_bufsize = zdr_decode_bufsize;

        if (iovcnt_hint > RPC_FAST_VECTORS) {
                pdu->out.iov = (struct rpc_iovec *) calloc(iovcnt_hint, sizeof(struct rpc_iovec));
                if (pdu->out.iov == NULL) {
                    rpc_set_error(rpc, "Out of memory: Failed to allocate out.iov");
                    goto failed2;
                }
                pdu->out.iov_capacity = iovcnt_hint;
        } else {
                pdu->out.iov = pdu->out.fast_iov;
                pdu->out.iov_capacity = RPC_FAST_VECTORS;
        }

        /*
         * Rest of the code depends on this, so assert it here.
         * If the caller uses this pdu for issuing a zero-copy READ,
         * pdu->in.base will be set to point to the dynamically allocated
         * iovec array.
         */
        assert(pdu->in.base == NULL);

	pdu->outdata.data = ((char *)pdu + pdu_size);

        /* Add an iovector for the record marker. Ignored for UDP */
        rpc_add_iovector(rpc, &pdu->out, pdu->outdata.data, 4, NULL);

        zdrmem_create(&pdu->zdr, &pdu->outdata.data[4],
                      ZDR_ENCODEBUF_MINSIZE + alloc_hint, ZDR_ENCODE);

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.xid                = pdu->xid;
        msg.direction          = CALL;
	msg.body.cbody.rpcvers = RPC_MSG_VERSION;
	msg.body.cbody.prog    = program;
	msg.body.cbody.vers    = version;
	msg.body.cbody.proc    = procedure;

	pdu->do_not_retry      = (program != NFS_PROGRAM);

	/* For NULL RPC RFC recommends to use NULL authentication */
	if (procedure == 0) {
		msg.body.cbody.cred.oa_flavor    = AUTH_NONE;
		msg.body.cbody.cred.oa_length    = 0;
		msg.body.cbody.cred.oa_base      = NULL;
		/*
		 * NULL RPC is like a ping which is sent right after connection
		 * establishment. The transport is still not used for sending
		 * other RPCs. It's best not to retry NULL RPC and let the caller
		 * truthfully know about the transport status.
		 */
		pdu->do_not_retry                = TRUE;
	} else {
		msg.body.cbody.cred    = rpc->auth->ah_cred;
	}

	msg.body.cbody.verf    = rpc->auth->ah_verf;

#ifdef HAVE_TLS
	/* Should not be already set */
	assert(pdu->expect_starttls == FALSE);

	if (send_auth_tls) {
		msg.body.cbody.cred.oa_flavor    = AUTH_TLS;
		msg.body.cbody.cred.oa_length    = 0;
		msg.body.cbody.cred.oa_base      = NULL;

		pdu->expect_starttls 		 = TRUE;
        }
#endif /* HAVE_TLS */

#ifdef HAVE_LIBKRB5
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
        if (rpc->sec != RPC_SEC_UNDEFINED) {
                ZDR tmpzdr;
                int level = RPC_GSS_SVC_NONE;

                pdu->gss_seqno = rpc->gss_seqno;

                zdrmem_create(&tmpzdr, pdu->creds, 64, ZDR_ENCODE);
                switch (rpc->sec) {
                case RPC_SEC_UNDEFINED:
                        break;
                case RPC_SEC_KRB5:
                        level = RPC_GSS_SVC_NONE;
                        break;
                case RPC_SEC_KRB5I:
                        if (pdu->gss_seqno > 0) {
                                level = RPC_GSS_SVC_INTEGRITY;
                        }
                        break;
                case RPC_SEC_KRB5P:
                        if (pdu->gss_seqno > 0) {
                                level = RPC_GSS_SVC_PRIVACY;
                        }
                        break;
                }
                if (libnfs_authgss_gen_creds(rpc, &tmpzdr, level) < 0) {
                        zdr_destroy(&tmpzdr);
                        rpc_set_error(rpc, "zdr_callmsg failed with %s",
                                      rpc_get_error(rpc));
                        goto failed;
                }
                msg.body.cbody.cred.oa_flavor = AUTH_GSS;
                msg.body.cbody.cred.oa_length = tmpzdr.pos;
                msg.body.cbody.cred.oa_base = pdu->creds;
                zdr_destroy(&tmpzdr);

                rpc->gss_seqno++;
                if (rpc->gss_seqno > 1) {
                        msg.body.cbody.verf.oa_flavor = AUTH_GSS;
                        msg.body.cbody.verf.gss_context = rpc->gss_context;
                }
        }
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
#endif /* HAVE_LIBKRB5 */

	if (zdr_callmsg(rpc, &pdu->zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_callmsg failed with %s",
			      rpc_get_error(rpc));
                goto failed;
	}

#ifdef HAVE_LIBKRB5
        switch (rpc->sec) {
        case RPC_SEC_UNDEFINED:
        case RPC_SEC_KRB5:
                break;
        case RPC_SEC_KRB5P:
        case RPC_SEC_KRB5I:
                if (pdu->gss_seqno > 0) {
                        pdu->start_of_payload = zdr_getpos(&pdu->zdr);
                        val = 0; /* dummy length, will fill in below once we know */
                        if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                                goto failed;
                       }
                        val = pdu->gss_seqno;
                        if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                                goto failed;
                        }
                }
                break;
        }
#endif /* HAVE_LIBKRB5 */

        /* Add an iovector for the header */
        rpc_add_iovector(rpc, &pdu->out, &pdu->outdata.data[4],
                         zdr_getpos(&pdu->zdr), NULL);

        /* Freshly allocated PDU cannot be retransmitted */
        assert(!pdu->is_retransmitted);

	return pdu;
 failed:
        rpc_set_error(rpc, "zdr_callmsg failed with %s",
                      rpc_get_error(rpc));
        zdr_destroy(&pdu->zdr);
 failed2:
        free(pdu);
        return NULL;
}

struct rpc_pdu *rpc_allocate_pdu(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize)
{
	return rpc_allocate_pdu2(rpc, program, version, procedure, cb, private_data, zdr_decode_fn, zdr_decode_bufsize, 0, 0);
}

void rpc_free_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
#ifdef HAVE_LIBKRB5
        uint32_t min;
#endif /* HAVE_LIBKRB5 */

	assert(rpc->magic == RPC_CONTEXT_MAGIC);
        /*
         * AZAUTH RPC is the only one queued with head priority and
         * AZAUTH RPC MUST only be sent if use_azauth is true.
         */
        assert(!pdu->is_head_prio || rpc->use_azauth);

#ifdef ENABLE_PARANOID
        /* PDU must be freed only after removing from all queues */
        assert(pdu->in_outqueue == PDU_ABSENT);
        assert(pdu->in_waitpdu == PDU_ABSENT);
#endif

	if (pdu->zdr_decode_buf != NULL) {
		zdr_free(pdu->zdr_decode_fn, pdu->zdr_decode_buf);
	}

#ifdef HAVE_LIBKRB5
        gss_release_buffer(&min, &pdu->output_buffer);
#endif /* HAVE_LIBKRB5 */
	zdr_destroy(&pdu->zdr);

        rpc_free_iovector(rpc, &pdu->out);
        rpc_free_cursor(rpc, &pdu->in);
        free(pdu);
}

void rpc_set_next_xid(struct rpc_context *rpc, uint32_t xid)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	rpc->xid = xid;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

void pdu_set_timeout(struct rpc_context *rpc, struct rpc_pdu *pdu, uint64_t now_msecs)
{
	if (rpc->timeout <= 0) {
		/* RPC request never times out */
		pdu->timeout = 0;
		return;
	}

	/* If user hasn't passed the current time, get it now */
	if (now_msecs == 0) {
		now_msecs = rpc_current_time();
	}

	/*
	 * If pdu->timeout is 0 it means either this is the first time we are
	 * setting the timeout for this RPC request or it has already timed out.
	 * In both these cases we reset pdu->timeout to rpc->timeout from now.
	 * If pdu->timeout is not 0 it means that the RPC has not yet timed out
	 * and hence we leave it unchanged.
	 */
	if (pdu->timeout == 0) {
		pdu->timeout = now_msecs + rpc->timeout;
#ifndef HAVE_CLOCK_GETTIME
		/* If we do not have GETTIME we fallback to time() which
		 * has 1s granularity for its timestamps.
		 * We thus need to bump the timeout by 1000ms
		 * so that the PDU will timeout within 1.0 - 2.0 seconds.
		 * Otherwise setting a 1s timeout would trigger within
		 * 0.001 - 1.0s.
		 */
		pdu->timeout += 1000;
#endif
	}

        /*
         * On major timeout we reset both major_timeout and timeout.
         * Note that timeout can be updated multiple times before a major
         * timeout, depending on the value of rpc->retrans.
         */
	if (pdu->major_timeout == 0) {
		pdu->major_timeout = now_msecs + (rpc->timeout * rpc->retrans);
		pdu->timeout = now_msecs + rpc->timeout;
#ifndef HAVE_CLOCK_GETTIME
		pdu->major_timeout += 1000;
		pdu->timeout += 1000;
#endif
                /*
                 * Early on when rpc->retrans is not set or if user doesn't
                 * set rpc->retrans, make sure major_timeout is set same as
                 * timeout.
                 */
                if (pdu->major_timeout < pdu->timeout) {
                        pdu->major_timeout = pdu->timeout;
                }
	}
}

/**
 * Queue pdu to rpc->outqueue.
 * PDU is queued to the tail of outqueue unless high_prio is set, in which case
 * it's queued to the head of outqueue (safe against partially sent head pdu).
 * high_prio queueing may be useful for non-IO (non READ/WRITE) RPCs so they
 * can be promptly sent out and they do not have to wait behind possibly huge
 * number of WRITE/READ RPCs in the queue. Those (especially WRITE RPCs) can
 * take very large time causing commands like stat/ls/find etc to appear to
 * hang.
 */
int rpc_queue_pdu2(struct rpc_context *rpc, struct rpc_pdu *pdu, int prio)
{
	int i, size = 0, pos;
        uint32_t recordmarker;
        /*
         * First pdu added to an empty outqueue is special, as an optimization
         * we send it inline from here. Since there is no other pdu being sent
         * it's safe against mixing bytes from different pdus.
         * First high prio pdu is also sent inline even if there are other low
         * priority pdus present in outqueue.
         */
        bool_t send_now;
#ifdef HAVE_LIBKRB5
        uint32_t maj, min, val, len;
        gss_buffer_desc message_buffer, output_token;
        char *buf;
#endif /* HAVE_LIBKRB5 */

        assert(prio == PDU_Q_PRIO_LOW ||
               prio == PDU_Q_PRIO_HI ||
               prio == PDU_Q_PRIO_HEAD);

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

#ifdef HAVE_LIBKRB5
        switch (rpc->sec) {
        case RPC_SEC_UNDEFINED:
        case RPC_SEC_KRB5:
                break;
        case RPC_SEC_KRB5I:
                if (pdu->gss_seqno == 0) {
                        break;
                }
                pos = zdr_getpos(&pdu->zdr);
                zdr_setpos(&pdu->zdr, pdu->start_of_payload);
                val = pos - pdu->start_of_payload - 4;
                if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                zdr_setpos(&pdu->zdr, pos);

                /* checksum */
                message_buffer.length = zdr_getpos(&pdu->zdr) - pdu->start_of_payload - 4;
                message_buffer.value = zdr_getptr(&pdu->zdr) + pdu->start_of_payload + 4;
                maj = gss_get_mic(&min, rpc->gss_context,
                                  GSS_C_QOP_DEFAULT,
                                  &message_buffer,
                                  &output_token);
                if (maj != GSS_S_COMPLETE) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                buf = output_token.value;
                len = output_token.length;
                if (!libnfs_zdr_bytes(&pdu->zdr, &buf, &len, len)) {
                        gss_release_buffer(&min, &output_token);
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                gss_release_buffer(&min, &output_token);
                break;
        case RPC_SEC_KRB5P:
                if (pdu->gss_seqno == 0) {
                        break;
                }
                pos = zdr_getpos(&pdu->zdr);
                message_buffer.length = zdr_getpos(&pdu->zdr) - pdu->start_of_payload - 4;
                message_buffer.value = zdr_getptr(&pdu->zdr) + pdu->start_of_payload + 4;
                maj = gss_wrap (&min, rpc->gss_context, 1,
                                GSS_C_QOP_DEFAULT,
                                &message_buffer,
                                NULL,
                                &output_token);
                if (maj != GSS_S_COMPLETE) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                zdr_setpos(&pdu->zdr, pdu->start_of_payload);
                buf = output_token.value;
                len = output_token.length;
                if (!libnfs_zdr_bytes(&pdu->zdr, &buf, &len, len)) {
                        gss_release_buffer(&min, &output_token);
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                gss_release_buffer(&min, &output_token);
                break;
        }
#endif /* HAVE_LIBKRB5 */

        pos = zdr_getpos(&pdu->zdr);

        /*
         * Now that the RPC is about to be queued, set absolute timeout values
         * for it.
         */
        pdu_set_timeout(rpc, pdu, 0);

        for (i = 1; i < pdu->out.niov; i++) {
                size += pdu->out.iov[i].len;
        }
        pdu->out.total_size = size + 4;

        /* If we need to add any additional iovectors
         *
         * We expect to almost always add an iovector here for the remainder
         * of the outdata marshalling buffer.
         * The exception is WRITE where we add an explicit iovector instead
         * of marshalling it in ZDR. This so that we can do zero-copy for
         * the WRITE path.
         */
        if (pos > size) {
                int count = pos - size;

                if (rpc_add_iovector(rpc, &pdu->out,
                                     &pdu->outdata.data[pdu->out.total_size],
                                     count, NULL) < 0) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                pdu->out.total_size += count;
                size = pos;
        }

	/* write recordmarker */
        recordmarker = htonl(size | 0x80000000);
	memcpy(pdu->out.iov[0].buf, &recordmarker, 4);

        /* 4 bytes for the recordmarker */
        pdu->req_size = size + 4;

	/*
	 * For udp we dont queue, we just send it straight away.
	 *
	 * Another case where we send straight away is the AUTH_TLS NULL RPC.
	 * This is particularly important for the reconnect case where we want to
	 * ensure TLS handshake completes successfully before we can send any of
	 * the queued RPCs waiting. If we do not send here this AUTH_TLS NULL
	 * RPC will need to be queued before all other waiting RPCs and even then
	 * we need to be careful that we don't send any of those RPCs till the
	 * TLS handshake is completed and the connection is secure.
	 * Sending inline here makes the handling simpler in rpc_service().
	 */
	if (rpc->is_udp != 0
#ifdef HAVE_TLS
	    || pdu->expect_starttls
#endif
	) {
		unsigned int hash;

#ifdef HAVE_TLS
		if (pdu->expect_starttls) {
			/* Currently we don't support RPC-with-TLS over UDP */
			assert(!rpc->is_udp);
			assert(!rpc->is_broadcast);

			RPC_LOG(rpc, 2, "Sending AUTH_TLS NULL RPC (%lu bytes)",
					pdu->out.total_size);
		}
#endif

                if (rpc->is_broadcast) {
                        if (sendto(rpc->fd, pdu->zdr.buf, size, MSG_DONTWAIT,
                                   (struct sockaddr *)&rpc->udp_dest,
                                   sizeof(rpc->udp_dest)) < 0) {
                                rpc_set_error(rpc, "Sendto failed with errno %s", strerror(errno));
                                rpc_free_pdu(rpc, pdu);
                                return -1;
                        }
                } else {
                        /*
                         * For UDP we don't support vectored write and for TLS
                         * the data will be less, so RPC_FAST_VECTORS should
                         * be sufficient for both cases.
                         */
                        struct iovec iov[RPC_FAST_VECTORS];
                        int niov = pdu->out.niov;
                        /* No record marker for UDP */
                        struct iovec *iovp = (rpc->is_udp ? &iov[1] : &iov[0]);
                        const int iovn = (rpc->is_udp ? niov - 1 : niov);

                        assert(niov <= RPC_FAST_VECTORS);

                        for (i = 0; i < niov; i++) {
                                iov[i].iov_base = pdu->out.iov[i].buf;
                                iov[i].iov_len = pdu->out.iov[i].len;
                        }
                        if (writev(rpc->fd, iovp, iovn) < 0) {
                                rpc_set_error(rpc, "Sendto failed with errno %s", strerror(errno));
                                rpc_free_pdu(rpc, pdu);
                                return -1;
                        }
                }

		hash = rpc_hash_xid(rpc, pdu->xid);
#ifdef HAVE_MULTITHREADING
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_lock(&rpc->rpc_mutex);
                }
#endif /* HAVE_MULTITHREADING */
		rpc_enqueue(&rpc->waitpdu[hash], pdu);
		rpc->waitpdu_len++;

#ifdef ENABLE_PARANOID
                assert(pdu->in_outqueue == PDU_ABSENT);
                assert(pdu->in_waitpdu == PDU_ABSENT);
                pdu->in_waitpdu = PDU_PRESENT;
                pdu->added_to_waitpdu_at_line = __LINE__;
                pdu->added_to_waitpdu_at_time = rpc_wallclock_time();
#endif

#ifdef HAVE_MULTITHREADING
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_unlock(&rpc->rpc_mutex);
                }
#endif /* HAVE_MULTITHREADING */
		return 0;
	}

	pdu->outdata.size = size;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
        /* Fresh PDU being queued to outqueue, num_done must be 0 */
        assert(pdu->out.num_done == 0);

        if (prio == PDU_Q_PRIO_LOW) {
                rpc_add_to_outqueue_lowp(rpc, pdu);
        } else if (prio == PDU_Q_PRIO_HI) {
                rpc_add_to_outqueue_highp(rpc, pdu);
        } else {
                rpc_add_to_outqueue_headp(rpc, pdu);
        }

        send_now = (rpc->outqueue.head == pdu);

#ifdef ENABLE_PARANOID
        assert(pdu->in_waitpdu == PDU_ABSENT);
        assert(pdu->in_outqueue == PDU_ABSENT);
        pdu->in_outqueue = PDU_PRESENT;
        pdu->added_to_outqueue_at_line = __LINE__;
        pdu->added_to_outqueue_at_time = rpc_wallclock_time();
#endif

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

        /*
         * If only PDU or a high/head priority PDU, send inline.
         */
        if (send_now) {
                /*
                 * We need to check if the token has expired, before we issue
                 * the RPC, else we can have the following problem:
                 * - user has not used the mount for a long time, and in the
                 *   meantime the token expired.
                 * - now user uses the mount which issues a command from fuse.
                 * - the command comes here and since it's the first request
                 *   to be queued in outqueue, send_now is true and we send the
                 *   request over to the server.
                 * - server fails the requuest with "permission denied" as the
                 *   auth token has expired.
                 *
                 * If the token has expired we do not send the request, but
                 * instead wake up rpc_service() thread, which again calls
                 * rpc_auth_needs_refresh() and triggers a reconnect.
                 * This will queue the AZAUTH RPC ahead of this request,
                 * perform the reconnect and auth refresh and once the refresh
                 * is successful, issue this new request.
                 */
                if (rpc_auth_needs_refresh(rpc)) {
                        RPC_LOG(rpc, 2, "Waking up rpc_service to refresh "
                                        "auth token, not sending pdu %p",
                                        pdu);

                        /*
                         * Wakeup rpc_service() thread which will refresh the
                         * cert and issue the RPC after that.
                         */
                        uint64_t evwrite = 1;
                        [[maybe_unused]] ssize_t evbytes =
                                write(rpc_get_evfd(rpc), &evwrite, sizeof(evwrite));
                        assert(evbytes == 8);
                        return 0;
                }

                rpc_write_to_socket(rpc);
        }

	return 0;
}

int rpc_queue_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        return rpc_queue_pdu2(rpc, pdu, PDU_Q_PRIO_LOW);
}

static int rpc_process_reply(struct rpc_context *rpc, ZDR *zdr)
{
	struct rpc_msg msg;
        struct rpc_pdu *pdu = rpc->pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Client got a response for its request */
	INC_STATS(rpc, num_resp_rcvd);

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.body.rbody.reply.areply.verf = _null_auth;
	if (pdu->zdr_decode_bufsize > 0) {
		pdu->zdr_decode_buf = (char *)pdu + PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	}
	msg.body.rbody.reply.areply.reply_data.results.where = pdu->zdr_decode_buf;
	msg.body.rbody.reply.areply.reply_data.results.proc  = pdu->zdr_decode_fn;
#ifdef HAVE_LIBKRB5
        if (rpc->sec == RPC_SEC_KRB5I && pdu->gss_seqno > 0) {
                msg.body.rbody.reply.areply.reply_data.results.krb5i = 1;
        }
        if (rpc->sec == RPC_SEC_KRB5P && pdu->gss_seqno > 0) {
                msg.body.rbody.reply.areply.reply_data.results.krb5p = 1;
                msg.body.rbody.reply.areply.reply_data.results.output_buffer = &pdu->output_buffer;
                msg.body.rbody.reply.areply.verf.gss_context = rpc->gss_context;
        }
#endif
	if (zdr_replymsg(rpc, zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed in rpc_process_reply: "
			      "%s", rpc_get_error(rpc));
		pdu->cb(rpc, RPC_STATUS_ERROR, "Message rejected by server",
			pdu->private_data);
		if (pdu->zdr_decode_buf != NULL) {
			pdu->zdr_decode_buf = NULL;
		}
		return 0;
	}
	if (msg.body.rbody.stat != MSG_ACCEPTED) {
		pdu->cb(rpc, RPC_STATUS_ERROR, "RPC Packet not accepted by the server", pdu->private_data);
		return 0;
	}

        /*
         * resp_size must be set to at least the size of the decoded headers.
         * For READ RPCs it'll be more as it'll also include the data received.
         * For zero-copy reads resp_size will be updated later as we read data
         * bytes into the user zerop-copy buffer(s).
         */
        assert(pdu->resp_size >= zdr->pos);

	switch (msg.body.rbody.reply.areply.stat) {
	case SUCCESS:
		/* Last RPC response time for tracking RPC transport health */
		rpc->last_successful_rpc_response = rpc_current_time();
		if (pdu->snr_logged) {
			RPC_LOG(rpc, 1, "[pdu %p] Server %s OK",
				pdu, rpc->server);
		}

                /*
                 * pdu->in.base will be non-NULL if this pdu is used for
                 * zero-copy READ. In that case we still need to read the
                 * data from the socket into the user's zero-copy buffers,
                 * so don't complete it as yet. Caller will arrange to read
                 * the data and complete the PDU once completed.
                 */
                if (pdu->in.base) {
                        rpc->pdu->free_pdu = 1;
                        break;
                }

#ifdef HAVE_TLS
		/*
		 * If we are expecting STARTTLS that means we have sent AUTH_TLS
		 * NULL RPC which means user has selected xprtsec=[tls,mtls], in
		 * which case the server MUST support TLS else we must terminate
		 * the RPC session.
		 */
		if (pdu->expect_starttls) {
			const char *const starttls_str = "STARTTLS";
			const int starttls_len = 8;

			if (msg.body.rbody.reply.areply.verf.oa_flavor != AUTH_NONE) {
				RPC_LOG(rpc, 1, "Server sent bad verifier flavor (%d) in response "
					"to AUTH_TLS NULL RPC",
					msg.body.rbody.reply.areply.verf.oa_flavor);
				pdu->cb(rpc, RPC_STATUS_ERROR,
					"Server sent bad verifier flavor", pdu->private_data);
				break;
			} else if (msg.body.rbody.reply.areply.verf.oa_length != starttls_len ||
				   memcmp(msg.body.rbody.reply.areply.verf.oa_base,
					  starttls_str, starttls_len)) {
				RPC_LOG(rpc, 1, "Server does not support TLS");
				pdu->cb(rpc, RPC_STATUS_ERROR,
					"Server does not support TLS", pdu->private_data);
				break;
			}
		}
#endif /* HAVE_TLS */

#ifdef HAVE_LIBKRB5
                if (msg.body.rbody.reply.areply.verf.oa_flavor == AUTH_GSS) {
                        uint32_t maj, min;
                        gss_buffer_desc message_buffer, token_buffer;
                        uint32_t seqno;

                        /* This is the the gss token from the NULL reply
                         * that finished authentication.
                         */
                        if (pdu->gss_seqno == 0) {
                                struct rpc_gss_init_res *gir = (struct rpc_gss_init_res *)pdu->zdr_decode_buf;

                                rpc->context_len = gir->handle.handle_len;
                                free(rpc->context);
                                rpc->context = malloc(rpc->context_len);
                                if (rpc->context == NULL) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "Failed to allocate rpc->context", pdu->private_data);
                                        break;
                                }
                                memcpy(rpc->context, gir->handle.handle_val, rpc->context_len);

                                if (krb5_auth_request(rpc, rpc->auth_data,
                                                      (unsigned char *)gir->gss_token.gss_token_val,
                                                      gir->gss_token.gss_token_len) < 0) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "krb5_auth_request returned error", pdu->private_data);
                                        break;
                                }
                        }

                        if (pdu->gss_seqno > 0) {
                                seqno = htonl(pdu->gss_seqno);
                                message_buffer.value = (char *)&seqno;
                                message_buffer.length = 4;

                                token_buffer.value = msg.body.rbody.reply.areply.verf.oa_base;
                                token_buffer.length = msg.body.rbody.reply.areply.verf.oa_length;
                                maj = gss_verify_mic(&min,
                                                     rpc->gss_context,
                                                     &message_buffer,
                                                     &token_buffer,
                                                     GSS_C_QOP_DEFAULT);
                                if (maj) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "gss_verify_mic failed for the verifier", pdu->private_data);
                                        break;
                                }
                        }
                }
#endif
		pdu->cb(rpc, RPC_STATUS_SUCCESS, pdu->zdr_decode_buf, pdu->private_data);
		break;
	case PROG_UNAVAIL:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Program not available", pdu->private_data);
		break;
	case PROG_MISMATCH:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Program version mismatch", pdu->private_data);
		break;
	case PROC_UNAVAIL:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Procedure not available", pdu->private_data);
		break;
	case GARBAGE_ARGS:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Garbage arguments", pdu->private_data);
		break;
	case SYSTEM_ERR:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: System Error", pdu->private_data);
		break;
	default:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Unknown rpc response from server", pdu->private_data);
		break;
	}

	return 0;
}

static int rpc_send_error_reply(struct rpc_context *rpc,
                                struct rpc_msg *call,
                                enum accept_stat err,
                                int min_vers, int max_vers)
{
        struct rpc_pdu *pdu;
        struct rpc_msg res;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&res, 0, sizeof(struct rpc_msg));
	res.xid                                      = call->xid;
        res.direction                                = REPLY;
        res.body.rbody.stat                          = MSG_ACCEPTED;
        res.body.rbody.reply.areply.reply_data.mismatch_info.low  = min_vers;
        res.body.rbody.reply.areply.reply_data.mismatch_info.high = max_vers;
	res.body.rbody.reply.areply.verf             = _null_auth;
	res.body.rbody.reply.areply.stat             = err;

        if (rpc->is_udp) {
                /* send the reply back to the client */
                memcpy(&rpc->udp_dest, &rpc->udp_src, sizeof(rpc->udp_dest));
        }

        pdu  = rpc_allocate_reply_pdu(rpc, &res, 0);
        if (pdu == NULL) {
                rpc_set_error(rpc, "Failed to send error_reply: %s",
                              rpc_get_error(rpc));
                return -1;
        }
        rpc_queue_pdu(rpc, pdu);

        return 0;
}

int rpc_send_reply(struct rpc_context *rpc,
                   struct rpc_msg *call,
                   void *reply,
                   zdrproc_t encode_fn,
                   int alloc_hint)
{
        struct rpc_pdu *pdu;
        struct rpc_msg res;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&res, 0, sizeof(struct rpc_msg));
	res.xid                                      = call->xid;
        res.direction                                = REPLY;
        res.body.rbody.stat                          = MSG_ACCEPTED;
	res.body.rbody.reply.areply.verf             = _null_auth;
	res.body.rbody.reply.areply.stat             = SUCCESS;

        res.body.rbody.reply.areply.reply_data.results.where = reply;
	res.body.rbody.reply.areply.reply_data.results.proc  = encode_fn;

        if (rpc->is_udp) {
                /* send the reply back to the client */
                memcpy(&rpc->udp_dest, &rpc->udp_src, sizeof(rpc->udp_dest));
        }

        pdu  = rpc_allocate_reply_pdu(rpc, &res, alloc_hint);
        if (pdu == NULL) {
                rpc_set_error(rpc, "Failed to send error_reply: %s",
                              rpc_get_error(rpc));
                return -1;
        }
        rpc_queue_pdu(rpc, pdu);

        return 0;
}

static int rpc_process_call(struct rpc_context *rpc, ZDR *zdr)
{
	struct rpc_msg call;
        struct rpc_endpoint *endpoint;
        int i, min_version = 0, max_version = 0, found_program = 0;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&call, 0, sizeof(struct rpc_msg));
	if (zdr_callmsg(rpc, zdr, &call) == 0) {
		rpc_set_error(rpc, "Failed to decode CALL message. %s",
                              rpc_get_error(rpc));
                return rpc_send_error_reply(rpc, &call, GARBAGE_ARGS, 0, 0);
        }
        for (endpoint = rpc->endpoints; endpoint; endpoint = endpoint->next) {
                if (call.body.cbody.prog == endpoint->program) {
                        if (!found_program) {
                                min_version = max_version = endpoint->version;
                        }
                        if (endpoint->version < min_version) {
                                min_version = endpoint->version;
                        }
                        if (endpoint->version > max_version) {
                                max_version = endpoint->version;
                        }
                        found_program = 1;
                        if (call.body.cbody.vers == endpoint->version) {
                                break;
                        }
                }
        }
        if (endpoint == NULL) {
		rpc_set_error(rpc, "No endpoint found for CALL "
                              "program:0x%08x version:%d\n",
                              (int)call.body.cbody.prog,
                              (int)call.body.cbody.vers);
                if (!found_program) {
                        return rpc_send_error_reply(rpc, &call, PROG_UNAVAIL,
                                                    0, 0);
                }
                return rpc_send_error_reply(rpc, &call, PROG_MISMATCH,
                                            min_version, max_version);
        }
        for (i = 0; i < endpoint->num_procs; i++) {
                if (endpoint->procs[i].proc == call.body.cbody.proc) {
                        if (endpoint->procs[i].decode_buf_size) {
                                call.body.cbody.args = zdr_malloc(zdr, endpoint->procs[i].decode_buf_size);
                                memset(call.body.cbody.args, 0, endpoint->procs[i].decode_buf_size);
                        }
                        if (!endpoint->procs[i].decode_fn(zdr, call.body.cbody.args)) {
                                rpc_set_error(rpc, "Failed to unmarshall "
                                              "call payload");
                                return rpc_send_error_reply(rpc, &call, GARBAGE_ARGS, 0 ,0);
                        }
                        return endpoint->procs[i].func(rpc, &call, endpoint->procs[i].opaque);
                }
        }

        return rpc_send_error_reply(rpc, &call, PROC_UNAVAIL, 0 ,0);
}

struct rpc_pdu *rpc_find_pdu(struct rpc_context *rpc, uint32_t xid)
{
	struct rpc_pdu *pdu, *prev_pdu;
	struct rpc_queue *q;
	unsigned int hash;

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

	/* Look up the transaction in a hash table of our requests */
	hash = rpc_hash_xid(rpc, rpc->rm_xid[1]);
	q = &rpc->waitpdu[hash];

	/* Follow the hash chain.  Linear traverse singly-linked list,
	 * but track previous entry for optimised removal */
	prev_pdu = NULL;
	for (pdu=q->head; pdu; pdu=pdu->next) {

#ifdef ENABLE_PARANOID
                assert(pdu->in_outqueue == PDU_ABSENT);
                assert(pdu->in_waitpdu == PDU_PRESENT);
#endif

		if (pdu->xid != rpc->rm_xid[1]) {
			prev_pdu = pdu;
			continue;
		}
		if (rpc->is_udp == 0 || rpc->is_broadcast == 0) {
			/* Singly-linked but we track head and tail */
			if (pdu == q->head)
				q->head = pdu->next;
			if (pdu == q->tail)
				q->tail = prev_pdu;
			if (prev_pdu != NULL)
				prev_pdu->next = pdu->next;
			rpc->waitpdu_len--;

#ifdef ENABLE_PARANOID
                        pdu->in_waitpdu = PDU_ABSENT;
                        pdu->removed_from_waitpdu_at_line = __LINE__;
                        pdu->removed_from_waitpdu_at_time = rpc_wallclock_time();
#endif

		}
                break;
        }

        if (pdu) {
                pdu->next = NULL;
        }

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

        return pdu;
}

bool_t rpc_pdu_is_retransmitted(struct rpc_pdu *pdu)
{
        return pdu->is_retransmitted;
}

uint32_t rpc_pdu_get_req_size(struct rpc_pdu *pdu)
{
        return pdu->req_size;
}

uint32_t rpc_pdu_get_resp_size(struct rpc_pdu *pdu)
{
        return pdu->resp_size;
}

uint64_t rpc_pdu_get_dispatch_usecs(struct rpc_pdu *pdu)
{
#ifdef HAVE_CLOCK_GETTIME
        return pdu->dispatch_usecs;
#else
        return 0;
#endif
}

int rpc_cancel_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        /*
         * Use rpc_find_pdu() to locate it and remove it from the input list.
         */
        pdu = rpc_find_pdu(rpc, pdu->xid);
        if (pdu) {
                rpc_free_pdu(rpc, pdu);
                return 0;
        }

        return -ENOENT;
}

int rpc_process_pdu(struct rpc_context *rpc, char *buf, int size)
{
	ZDR zdr;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&zdr, 0, sizeof(ZDR));

	zdrmem_create(&zdr, buf, size, ZDR_DECODE);
        if (rpc->is_server_context) {
                int ret;

                ret = rpc_process_call(rpc, &zdr);
                zdr_destroy(&zdr);
                return ret;
        }

        if (rpc_process_reply(rpc, &zdr) != 0) {
                rpc_set_error(rpc, "rpc_procdess_reply failed");
        }

        if (rpc->fragments == NULL && rpc->pdu && rpc->pdu->in.base) {
                memcpy(&rpc->pdu->zdr, &zdr, sizeof(zdr));
                rpc->pdu->free_zdr = 1;
        } else {
                zdr_destroy(&zdr);
        }
        return 0;
}

#ifdef ENABLE_PARANOID
/*
 * Perfom extensive validation on the rpc_context and the various pdu queues.
 * This helps to catch bugs related to pdu queues.
 * rpc->rpc_mutex exclusive lock must be held by the caller.
 */
void rpc_paranoid_checks(struct rpc_context *rpc)
{
        struct rpc_pdu *pdu, *next_pdu, *last_pdu = NULL;
        struct rpc_pdu *last_highprio_pdu = NULL;
        int outqueue_count = 0;
        int waitpdu_count = 0;
        int i;

        for (pdu = rpc->outqueue.head; pdu; pdu = pdu->next) {
                /*
                 * Must be present in outqueue and not waitpdu queue.
                 */
                assert(pdu->in_outqueue == PDU_PRESENT);
                assert(pdu->in_waitpdu == PDU_ABSENT);

                /*
                 * Fully sent PDU should not be sitting in outqueue.
                 */
                assert(pdu->out.num_done < pdu->out.total_size);

                /*
                 * added_to_outqueue_at_time must be the latest.
                 */
                assert(pdu->added_to_outqueue_at_time >
                                pdu->removed_from_outqueue_at_time);
                assert(pdu->added_to_outqueue_at_time >
                                pdu->added_to_waitpdu_at_time);
                assert(pdu->added_to_outqueue_at_time >=
                                pdu->removed_from_waitpdu_at_time);
                outqueue_count++;
                last_pdu = pdu;
                if (pdu->is_high_prio)
                        last_highprio_pdu = pdu;
        }
        assert(rpc->stats.outqueue_len == outqueue_count);
        assert(rpc->outqueue.tail == last_pdu);
        assert(rpc->outqueue.tailp == last_highprio_pdu);

        for (i = 0; i < rpc->num_hashes; i++) {
                struct rpc_queue *q = &rpc->waitpdu[i];
                last_pdu = NULL;
                for (pdu = q->head; pdu; pdu = next_pdu) {
                        next_pdu = pdu->next;

                        /*
                         * Must be present in waitpdu queue and not outqueue.
                         */
                        assert(pdu->in_waitpdu == PDU_PRESENT);
                        assert(pdu->in_outqueue == PDU_ABSENT);

                        /*
                         * Only fully sent PDU should be sitting in waitpdu hash.
                         */
                        assert(pdu->out.num_done == pdu->out.total_size);

                        /*
                         * added_to_outqueue_at_time must be the latest.
                         */
                        assert(pdu->added_to_waitpdu_at_time >
                                        pdu->removed_from_waitpdu_at_time);
                        assert(pdu->added_to_waitpdu_at_time >
                                        pdu->added_to_outqueue_at_time);
                        assert(pdu->added_to_waitpdu_at_time >=
                                        pdu->removed_from_outqueue_at_time);

                        waitpdu_count++;
                        last_pdu = pdu;
                }
                assert(q->tail == last_pdu);
        }

        assert(rpc->waitpdu_len == waitpdu_count);
}
#endif

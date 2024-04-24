/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/in.h>
#include <gnutls/gnutls.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "tls-private.h"

#ifdef _GNU_SOURCE
#define GETENV secure_getenv
#else
#define GETENV getenv
#endif

static bool_t global_init_done;
static gnutls_certificate_credentials_t xcred;
static bool_t tls_global_init_done;

int tls_log_level;

static void libnfs_gnutls_audit_func(gnutls_session_t session, const char *msg)
{
	fprintf(stderr, "gnutls audit [%p]: %s\n", session, msg);
}

/*
 * Global/onetime TLS specific initializations.
 * MUST be called if user selected xprtsec=[tls,mtls] mount option.
 */
int tls_global_init(struct rpc_context *rpc)
{
	const char *trusted_ca_file;
	const char *trusted_ca_dir;
	const char *client_cert_file;
	const char *client_key_file;
	int total_certs_loaded = 0;
	int ret;

	/* All but the first successful call will be a no-op */
	if (tls_global_init_done)
		return 0;

	/* Based on various gnutls functions we call this is the min version */
	if (gnutls_check_version("3.4.6") == NULL) {
		TLS_LOG(1, "tls_global_init: GnuTLS 3.4.6 or later is required");
		return -1;
	}

	TLS_LOG(2, "Using GnuTLS version %s", gnutls_check_version("0.0.0"));

	/*
	 * XXX See if we need a separate log level for gnutls, but for now
	 *     let's use the libnfs debug level which is still pretty usable
	 *     as it allows us to control the loglevel using debug= option.
	 *
	 *     This can be overridden using env variable "GNUTLS_DEBUG_LEVEL".
	 */
	tls_log_level = rpc->debug;
	gnutls_global_set_log_level(tls_log_level);
	gnutls_global_set_audit_log_function(libnfs_gnutls_audit_func);

	/* For backwards compatibility with gnutls < 3.3.0 */
	ret = gnutls_global_init();
	if (ret < 0) {
		TLS_LOG(1, "tls_global_init: gnutls_global_init() failed (%d)", ret);
		return -1;
	}
	/* Now gnutls_global_deinit() can be safely called */
	global_init_done = TRUE;

	/* X509 stuff */
	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret < 0) {
		TLS_LOG(1, "tls_global_init: gnutls_certificate_allocate_credentials() failed (%d)", ret);
		goto failed;
	}

	total_certs_loaded = 0;

	/* Load trusted CA certs from system trust store for Internet PKI */
	ret = gnutls_certificate_set_x509_system_trust(xcred);
	if (ret < 0) {
		TLS_LOG(1, "tls_global_init: gnutls_certificate_set_x509_system_trust() failed (%d)", ret);
		/* Don't fail as yet, we fail if we are not able to load any certs from any sources */
	} else {
		TLS_LOG(2, "tls_global_init: Loaded %d certificate(s) from system trust store", ret);
		total_certs_loaded += ret;
	}

	trusted_ca_dir = GETENV("LIBNFS_TLS_TRUSTED_CA_DIR");
	if (trusted_ca_dir != NULL) {
		ret = gnutls_certificate_set_x509_trust_dir(xcred, trusted_ca_dir, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			TLS_LOG(1, "tls_global_init: gnutls_certificate_set_x509_trust_dir(%s) failed (%d)",
				trusted_ca_dir, ret);
			/* Don't fail as yet, we fail if we are not able to load any certs from any sources */
		} else {
			TLS_LOG(2, "tls_global_init: Loaded %d certificate(s) from dir %s", ret, trusted_ca_dir);
			total_certs_loaded += ret;
		}
	}

	trusted_ca_file = GETENV("LIBNFS_TLS_TRUSTED_CA_PEM");
	if (trusted_ca_file != NULL) {
		ret = gnutls_certificate_set_x509_trust_file(xcred, trusted_ca_file, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			TLS_LOG(1, "tls_global_init: gnutls_certificate_set_x509_trust_file(%s) failed (%d)",
				trusted_ca_file, ret);
			/* Don't fail as yet, we fail if we are not able to load any certs from any sources */
		} else {
			TLS_LOG(2, "tls_global_init: Loaded %d certificate(s) from file %s", ret, trusted_ca_file);
			total_certs_loaded += ret;
		}
	}

	/* If no certs loaded, there's no point in proceeding */
	if (total_certs_loaded == 0) {
		TLS_LOG(1, "tls_global_init: No CA certs loaded, make sure your system trust store is setup "
			        "correctly and/or you have correctly set the LIBNFS_TLS_TRUSTED_CA_DIR and/or "
			        "LIBNFS_TLS_TRUSTED_CA_PEM env variables!");
		goto failed;
	}

	/* If client holds a certificate it can be set using the following:
	 */
	client_cert_file = GETENV("LIBNFS_TLS_CLIENT_CERT_PEM");
	client_key_file = GETENV("LIBNFS_TLS_CLIENT_KEY_PEM");
	
	if (client_cert_file && client_key_file) {
		ret = gnutls_certificate_set_x509_key_file(xcred, client_cert_file, client_key_file,
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			TLS_LOG(1, "tls_global_init: gnutls_certificate_set_x509_key_file(%s, %s) failed (%d)",
				client_cert_file, client_key_file, ret);
			goto failed;
		}
	} else if (client_cert_file) {
		TLS_LOG(1, "tls_global_init: Client cert specified (%s) but not key, mtls cannot be used",
			client_cert_file);
	} else if (client_key_file) {
		TLS_LOG(1, "tls_global_init: Client key specified (%s) but not cert, mtls cannot be used",
			client_key_file);
	} else {
		TLS_LOG(2, "tls_global_init: Client cert and key not specified, mtls cannot be used");
	}

	tls_global_init_done = TRUE;
	return 0;

failed:
	gnutls_certificate_free_credentials(xcred);

	if (global_init_done) {
		gnutls_global_deinit();
		global_init_done = -1;
	}

	return -1;
}

/*
 * Sets nagle to 'val' and returns the existing value.
 * val==0 will turn off nagle and value==1 will turn it on.
 */
static int tls_set_nagle(int sockfd, int val)
{
	int saved_nagle;
	socklen_t len = sizeof(saved_nagle);

	if (getsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &saved_nagle, &len) != 0) {
		TLS_LOG(1, "getsockopt(TCP_NODELAY) failed(%d): %s", errno, strerror(errno));
		return -1;
	}

	if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0) {
		TLS_LOG(1, "setsockopt(TCP_NODELAY, %d) failed(%d): %s", val, errno, strerror(errno));
		return -1;
	}

	return saved_nagle;
}

/*
 * This is the TLS handshake routine. It can be called after the TCP connection
 * is established. It performs TLS handshake with the server in async manner,
 * so this can return TLS_HANDSHAKE_IN_PROGRESS multiple times and it's safe to
 * call it till it returns TLS_HANDSHAKE_COMPLETED or TLS_HANDSHAKE_FAILED.
 */
enum tls_handshake_state
do_tls_handshake(struct rpc_context *rpc)
{
	int ret, saved_nagle, type;
	char *desc;
	const int sd = rpc_get_fd(rpc);
	unsigned int status;
	const char *server_sni = rpc->server;
	const char *priority_string;
	/* gnutls session performing the handshake */
	gnutls_session_t session = rpc->tls_context.session;
	gnutls_datum_t out;

	if (!tls_global_init_done) {
		TLS_LOG(1, "do_tls_handshake: tls_global_init() not done!");
		/* Should not happen */
		assert(0);
		return TLS_HANDSHAKE_FAILED;
	}

	/* XXX: Are people still using NFS over UDP? */
	if (rpc->is_udp) {
		TLS_LOG(1, "do_tls_handshake: UDP transport not supported");
		return TLS_HANDSHAKE_FAILED;
	}

	/* do_tls_handshake() must be called only after server name is set */
	if (server_sni == NULL) {
		TLS_LOG(1, "do_tls_handshake: Server name not set");
		return TLS_HANDSHAKE_FAILED;
	}

	/* and we are connected */
	if (sd == -1) {
		TLS_LOG(1, "do_tls_handshake: rpc->fd is -1");
		return TLS_HANDSHAKE_FAILED;
	}

	if (!rpc->is_connected) {
		TLS_LOG(1, "do_tls_handshake: rpc is not connected");
		return TLS_HANDSHAKE_FAILED;
	}

	/*
	 * First time we are called session would not exist, create and populate one.
	 */
	if (rpc->tls_context.session == NULL) {
		/* Initialize TLS session */
		ret = gnutls_init(&rpc->tls_context.session, GNUTLS_CLIENT);
		if (ret < 0) {
			TLS_LOG(1, "do_tls_handshake: gnutls_init() failed(%d)", ret);
			return TLS_HANDSHAKE_FAILED;
		}

		ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, server_sni, strlen(server_sni));
		if (ret < 0) {
			TLS_LOG(1, "do_tls_handshake: gnutls_server_name_set(%s) failed(%d)",
				server_sni, ret);
			return TLS_HANDSHAKE_FAILED;
		}

		/*
		 * LIBNFS_TLS_GNUTLS_PRIORITY_STRING should be set to a valid gnutls priority
		 * string. Make sure the following confirms validity of the priority string:
		 * # gnutls-cli -l --priority="$LIBNFS_TLS_GNUTLS_PRIORITY_STRING"
		 */
		priority_string = GETENV("LIBNFS_TLS_GNUTLS_PRIORITY_STRING");
		if (priority_string == NULL) {
			priority_string = "PERFORMANCE:-CIPHER-ALL:+AES-128-GCM";
			ret = gnutls_priority_set_direct(session, priority_string, NULL);
			if (ret < 0) {
				TLS_LOG(1, "do_tls_handshake: gnutls_priority_set_direct(%s) failed(%d)",
					priority_string, ret);
				return TLS_HANDSHAKE_FAILED;
			}
		} else if (strcmp(priority_string, "default") == 0) {
			ret = gnutls_set_default_priority(session);
				TLS_LOG(1, "do_tls_handshake: gnutls_set_default_priority() failed(%d)",
					ret);
		} else {
			ret = gnutls_priority_set_direct(session, priority_string, NULL);
			if (ret < 0) {
				TLS_LOG(1, "do_tls_handshake: gnutls_priority_set_direct(%s) failed(%d)",
					priority_string, ret);
				return TLS_HANDSHAKE_FAILED;
			}
		}

		/* Put the x509 credentials to the current session */
		ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
		if (ret < 0) {
			TLS_LOG(1, "do_tls_handshake: gnutls_credentials_set() failed(%d)", ret);
			return TLS_HANDSHAKE_FAILED;
		}

		gnutls_session_set_verify_cert(session, server_sni, 0);

		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	}

	gnutls_transport_set_int(session, sd);

	/* Disable nagle for faster handshake */
	saved_nagle = tls_set_nagle(sd, 0);

	/* Perform the TLS handshake */
	ret = gnutls_handshake(session);

	tls_set_nagle(sd, saved_nagle);

	if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
			/* check certificate verification status */
			type = gnutls_certificate_type_get(session);
			status = gnutls_session_get_verify_cert_status(session);
			ret = gnutls_certificate_verification_status_print(status, type, &out, 0);
			TLS_LOG(2, "cert verify output: %s", out.data);
			gnutls_free(out.data);
			TLS_LOG(1, "*** Handshake failed: %s", gnutls_strerror(ret));
			return TLS_HANDSHAKE_FAILED;
		} else if (gnutls_error_is_fatal(ret)) {
			TLS_LOG(1, "*** Handshake failed: %s", gnutls_strerror(ret));
			return TLS_HANDSHAKE_FAILED;
		} else {
			return TLS_HANDSHAKE_IN_PROGRESS;
		}
	} else {
		TLS_LOG(2, "+++ Handshake successful +++");
		desc = gnutls_session_get_desc(session);
		TLS_LOG(2, "Session info: %s", desc);
		gnutls_free(desc);
	}

	/* Install the security parameters into kTLS */
	ret = setup_ktls(session);
	if (ret < 0) {
		TLS_LOG(1, "do_tls_handshake: setup_ktls() failed(%d)", ret);
		return TLS_HANDSHAKE_FAILED;
	}

	return TLS_HANDSHAKE_COMPLETED;
}

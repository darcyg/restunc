/**
 * @file main.c  STUN Client
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#ifdef SOLARIS
#define __EXTENSIONS__ 1
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_GETOPT
#include <getopt.h>
#endif
#include <re.h>
#include "stunc.h"


#define DEBUG_MODULE "restunc"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static struct {
	struct stun_conf conf;
	const char *username;
	const char *password;
	struct sa laddr;
	const char *server;
	uint16_t port;
	int af;
	const char *dest;
	struct dnsc *dnsc;
	struct stun_dns *dns;
	int proto;
	struct udp_sock *us;
	struct sa srv;
	struct sa peer;
	uint16_t loop_port;
	uint32_t lifetime;

	/* Tests */
	struct stun_keepalive *ska;
} stunc;


union req req;


static int start_service(void);


static void signal_handler(int signum)
{
	(void)re_fprintf(stderr, "caught signal %d\n", signum);
	re_cancel();
}


void terminate_if_done(void)
{
	if (req.flags)
		return;

	re_cancel();
}


/* STUN Binding Request */


static void mapped_addr_handler(int err, const struct sa *map, void *arg)
{
	(void)arg;

	if (err) {
		DEBUG_WARNING("Mapped address error (%s)\n", strerror(err));
	}
	else {
		(void)re_fprintf(stderr, "Mapped address: %J\n", map);
	}

	req.f.bd = false;
	terminate_if_done();
}


static void do_bindisc(void)
{
	int err;

	(void)re_fprintf(stderr, "Doing Binding Discovery test..\n");

	err = stun_keepalive_alloc(&stunc.ska, stunc.proto, stunc.us, 0,
				   &stunc.srv, &stunc.conf,
				   mapped_addr_handler, NULL);
	if (err) {
		DEBUG_WARNING("keepalive alloc (%s)\n", strerror(err));
		goto error;
	}

	stun_keepalive_enable(stunc.ska, 10);

	return;

 error:
	req.f.bd = false;
}


static void do_ice(void)
{
	int err;

	err = ice_test(&stunc.srv, stunc.proto,
		       stunc.username, stunc.password);
	if (err) {
		DEBUG_WARNING("ICE test: %s\n", strerror(err));
		req.f.ice = false;
	}
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	(void)src;
	(void)mb;
	(void)arg;

	DEBUG_INFO("UDP response from %J\n", src);
}


static void stunc_close(void)
{
#ifndef WIN32
	fd_close(STDIN_FILENO);
#endif

	ice_close();
	turn_close();
	natbd_close();

	stunc.ska = mem_deref(stunc.ska);
	stunc.us = mem_deref(stunc.us);

	stunc.dns  = mem_deref(stunc.dns);
	stunc.dnsc = mem_deref(stunc.dnsc);

	libre_close();
}


static int dns_init(void)
{
	struct sa nsv[4];
	uint32_t nsn;
	int err;

	nsn = ARRAY_SIZE(nsv);

	err = dns_srv_get(NULL, 0, nsv, &nsn);
	if (err) {
		DEBUG_WARNING("dns_srv_get: %s\n", strerror(err));
		goto out;
	}

	err = dnsc_alloc(&stunc.dnsc, NULL, nsv, nsn);
	if (err) {
		DEBUG_WARNING("dnsc_alloc: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}


static int stunc_init(void)
{
	int err;

	err = net_default_source_addr_get(stunc.af, &stunc.laddr);
	if (err) {
		DEBUG_WARNING("get source addr: %s\n", strerror(err));
	}

	(void)re_fprintf(stderr, "STUN client: local=%j srv=%s:%u (rto=%u)\n",
			 &stunc.laddr, stunc.server, stunc.port,
			 stunc.conf.rto);

	err = dns_init();
	if (err) {
		DEBUG_WARNING("dns init failed: %s\n", strerror(err));
		goto out;
	}

	err = turn_init(stunc.username, stunc.password,
			&stunc.peer, stunc.loop_port);
	if (err)
		goto out;

	natbd_init(&stunc.laddr, &stunc.srv, stunc.proto, &stunc.conf);

	err = start_service();
	if (err)
		goto out;

	return 0;

 out:
	DEBUG_WARNING("stun client err (%s)\n", strerror(err));
	stunc_close();
	return err;
}


static int stunc_init_udp(void)
{
	int err;

	err = udp_listen(&stunc.us, NULL, udp_recv, NULL);
	if (err) {
		DEBUG_WARNING("udp_listen: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}


static void stun_dns_handler(int err, const struct sa *srv, void *arg)
{
	(void)arg;

	if (err) {
		DEBUG_WARNING("Could not resolve STUN server %s (%s)\n",
			      stunc.server, strerror(err));
		req.flags = 0;
		goto out;
	}

	/* Copy STUN Server address */
	sa_cpy(&stunc.srv, srv);
	(void)re_fprintf(stderr, "Resolved STUN server: %J\n", &stunc.srv);

	/* Protocol init */
	switch (stunc.proto) {

	case IPPROTO_UDP:
		err = stunc_init_udp();
		if (err) {
			DEBUG_WARNING("UDP init failed (%s)\n",
				      strerror(err));
			goto out;
		}
		if (req.f.bd)
			do_bindisc();
		if (req.f.nh)
			natbd_do_hairpinning();
		if (req.f.nm)
			natbd_do_mapping();
		if (req.f.nf)
			natbd_do_filtering();
		if (req.f.nl)
			natbd_do_lifetime();
		if (req.f.ga)
			natbd_do_genalg();
		if (req.f.ar)
			turn_start(&stunc.conf, stunc.proto, &stunc.srv,
				   stunc.lifetime);
		if (req.f.ice)
			do_ice();
		break;

	case IPPROTO_TCP:
		if (req.f.bd)
			do_bindisc();
		if (req.f.nh)
			natbd_do_hairpinning();
		if (req.f.nm)
			natbd_do_mapping();
		if (req.f.ga)
			natbd_do_genalg();
		if (req.f.ar)
			turn_start(&stunc.conf, stunc.proto, &stunc.srv,
				   stunc.lifetime);
		if (req.f.ice)
			do_ice();
		break;

	default:
		break;
	}

 out:
	stunc.dns = mem_deref(stunc.dns);
	terminate_if_done();
}


static int start_service(void)
{
	const char *service, *proto;
	int err;

	/* Determine which service to use */
	if (req.f.ice)
		service = stun_usage_binding;
	else if (req.f.ar)
		service = stun_usage_relay;
	else if (req.f.bd)
		service = stun_usage_binding;
	else
		service = stun_usage_behavior;

	/* Determine which transport protocol to use */
	switch (stunc.proto) {

	case IPPROTO_UDP:
		proto = stun_proto_udp;
		break;

	case IPPROTO_TCP:
		proto = stun_proto_tcp;
		break;

	default:
		(void)re_fprintf(stderr, "No transport specified"
				 " - UDP or TCP\n");
		return EPROTONOSUPPORT;
	}

	(void)re_printf("Service: \"%s\", Protocol: \"%s\"\n",
			service, proto);

	/* Do DNS Discovery of a STUN Server */
	err = stun_server_discover(&stunc.dns, stunc.dnsc, service, proto,
				   stunc.af, stunc.server, stunc.port,
				   stun_dns_handler, NULL);
	if (err) {
		DEBUG_WARNING("stun_server_discover failed (%s)\n",
			      strerror(err));
		return err;
	}

	return err;
}


#ifndef WIN32
static void stdin_handler(int flags, void *arg)
{
	(void)arg;

	if (!(flags & FD_READ))
		return;

	(void)getchar();

	if (req.f.ice)
		ice_test_debug();
}
#endif


#ifdef HAVE_GETOPT
static void usage(void)
{
	(void)re_fprintf(stderr, "Usage: restunc [-crhmflbkautUPRTD6]"
			 " [-p port] <server>\n");
	(void)re_fprintf(stderr, "options:\n");
	(void)re_fprintf(stderr, "\t-?         Help\n");
	(void)re_fprintf(stderr, "\t-p         Server port number\n");
	(void)re_fprintf(stderr, "\t-r         RTO in [ms] (default %u ms)\n",
			 stunc.conf.rto);
	(void)re_fprintf(stderr, "\t-a         Do all tests\n");
	(void)re_fprintf(stderr, "\t-u         UDP only\n");
	(void)re_fprintf(stderr, "\t-t         TCP only\n");
	(void)re_fprintf(stderr, "\t-6         Prefer IPv6\n");
	(void)re_fprintf(stderr, "\nBasic STUN options:\n");
	(void)re_fprintf(stderr, "\t-b         Do Binding Discovery\n");
	(void)re_fprintf(stderr, "\nNAT Behavior Discovery options:\n");
	(void)re_fprintf(stderr, "\t-h         Do hairpinning\n");
	(void)re_fprintf(stderr, "\t-m         Do mapping\n");
	(void)re_fprintf(stderr, "\t-f         Do filtering\n");
	(void)re_fprintf(stderr, "\t-l         Do lifetime discovery\n");
	(void)re_fprintf(stderr, "\t-g         Do Generic ALG detection\n");
	(void)re_fprintf(stderr, "\nTURN options:\n");
	(void)re_fprintf(stderr, "\t-T         Do TURN\n");
	(void)re_fprintf(stderr, "\t-U <user>  Username\n");
	(void)re_fprintf(stderr, "\t-P <pass>  Password\n");
	(void)re_fprintf(stderr, "\t-D <dest>  Destination (ip:port)\n");
	(void)re_fprintf(stderr, "\t-L <sec>   Lifetime in [sec]\n");
	(void)re_fprintf(stderr, "\t-O <port>  Local loop port\n");
	(void)re_fprintf(stderr, "\nICE options:\n");
	(void)re_fprintf(stderr, "\t-I         Do ICE test\n");
}
#endif


int main(int argc, char *argv[])
{
	bool ansi = true;
	int err = 0;

	stunc.conf.rto = STUN_DEFAULT_RTO;
	stunc.conf.rc  = STUN_DEFAULT_RC;
	stunc.conf.rm  = STUN_DEFAULT_RM;
	stunc.conf.ti  = STUN_DEFAULT_TI;
	stunc.conf.tos = 0x00;

	stunc.af = AF_INET;
	stunc.lifetime = TURN_DEFAULT_LIFETIME;

#ifdef HAVE_GETOPT
	for (;;) {
		int c;
		c = getopt(argc, argv, "?p:r:utbhmflgaTU:P:D:L:IO:6");
		if (0 > c)
			break;

		switch (c) {

		case '?':
			usage();
			return -2;

		case 'p':
			stunc.port = atoi(optarg);
			break;

		case 'r':
			stunc.conf.rto = atoi(optarg);
			break;

		case '6':
			stunc.af = AF_INET6;
			break;

		case 'u':
			stunc.proto = IPPROTO_UDP;
			break;

		case 't':
			stunc.proto = IPPROTO_TCP;
			break;

		case 'b':
			req.f.bd = true;
			break;

		case 'h':
			req.f.nh = true;
			break;

		case 'm':
			req.f.nm = true;
			break;

		case 'f':
			req.f.nf = true;
			break;

		case 'l':
			req.f.nl = true;
			break;

		case 'g':
			req.f.ga = true;
			break;

		case 'a':
			req.f.bd = true;
			req.f.nh = true;
			req.f.nm = true;
			req.f.nf = true;
			req.f.ga = true;
			break;

		case 'T':
			req.f.ar = true;
			break;

		case 'I':
			req.f.ice = true;
			break;

		case 'U':
			stunc.username = optarg;
			break;

		case 'P':
			stunc.password = optarg;
			break;

		case 'D':
			stunc.dest = optarg;
			break;

		case 'L':
			stunc.lifetime = atoi(optarg);
			break;

		case 'O':
			stunc.loop_port = atoi(optarg);
			break;

		default:
			break;
		}
	}

	if (argc < 2 || (argc != (optind + 1))) {
		usage();
		return -2;
	}

	stunc.server = argv[optind];
#else
	(void)argc;
	(void)argv;

	stunc.server = "creytiv.com";
	stunc.proto = IPPROTO_UDP;

	req.f.bd = true;
	req.f.nh = true;
	req.f.nm = true;
	req.f.nf = true;
	req.f.ga = true;
#endif

	/* Initialise debugging */
#if defined(WIN32) && !defined(CYGWIN)
	ansi = false;
#endif
	dbg_init(DBG_INFO, ansi ? DBG_ANSI : 0);

	/* Initialise System library */
	err = libre_init();
	if (err)
		goto out;

	(void)fd_setsize(1024);
	(void)sys_coredump_set(true);

	if (stunc.dest) {

		err = sa_decode(&stunc.peer, stunc.dest, strlen(stunc.dest));
		if (err) {
			DEBUG_WARNING("Could not parse %s (%s)\n",
				      stunc.dest, strerror(err));
			goto out;
		}
	}

	err = stunc_init();
	if (err)
		goto out;

#ifndef WIN32
	/* todo: bug with mingw32/winxp - select() returns ENOENT */
	(void)fd_listen(STDIN_FILENO, FD_READ, stdin_handler, NULL);
#endif

	err = re_main(signal_handler);

 out:
	if (err && EINTR != err) {
		DEBUG_WARNING("main loop left with: %s\n", strerror(err));
	}
	stunc_close();
	mem_debug();
	return err;
}

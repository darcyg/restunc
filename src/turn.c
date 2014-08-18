/**
 * @file turn.c  TURN Client
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include "stunc.h"


#define DEBUG_MODULE "turn"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static struct {
	struct udp_sock *us;
	const char *username;
	const char *password;
	const struct sa *peer;
	struct turnc *tc;

	/* Loop */
	struct udp_sock *loop_us;
	struct sa loop_local;
	struct sa loop_src;
} turnc;


static void turn_done(void)
{
	req.f.ar = false;
	terminate_if_done();
}


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay,
			  const struct sa *mapped,
			  const struct stun_msg *msg, void *arg)
{
	(void)msg;
	(void)arg;

	/* Transaction errors */
	if (err) {
		DEBUG_WARNING("TURN Client error: %m\n", err);
		turn_done();
		return;
	}

	/* STUN errors */
	if (scode) {
		DEBUG_WARNING("TURN Client error: %u %s\n", scode, reason);
		turn_done();
		return;
	}

	(void)re_fprintf(stderr, "Allocate Request: relay_addr=%J"
			 ", mapped_addr=%J\n", relay, mapped);

	if (sa_isset(turnc.peer, SA_ALL)) {
		(void)re_fprintf(stderr, "ChannelBind: %J\n", turnc.peer);

		err = turnc_add_chan(turnc.tc, turnc.peer, NULL, NULL);
		if (err) {
			DEBUG_WARNING("TURN add channel: %m\n", err);
		}
	}
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	int err;

	(void)src;
	(void)arg;

	err = udp_send(turnc.loop_us, &turnc.loop_src, mb);
	if (err) {
		DEBUG_WARNING("udp send: %m\n", err);
	}
}


static void udp_loop_recv(const struct sa *src, struct mbuf *mb,
			  void *arg)
{
	int err;

	(void)arg;

	sa_cpy(&turnc.loop_src, src);

	if (!turnc.tc) {
		DEBUG_WARNING("no turn client\n");
		return;
	}

	if (!sa_isset(turnc.peer, SA_ALL)) {
		DEBUG_WARNING("Peer not set\n");
		return;
	}

	err = udp_send(turnc.us, turnc.peer, mb);
	if (err) {
		DEBUG_WARNING("turnc send data: %m\n", err);
	}
}


int turn_init(const char *username, const char *password,
	      const struct sa *peer, uint16_t loop_port)
{
	int err = 0;

	turnc.username = username;
	turnc.password = password;
	turnc.peer = peer;

	err = udp_listen(&turnc.us, NULL, udp_recv, NULL);
	if (err) {
		DEBUG_WARNING("udp_listen: %m\n", err);
		goto out;
	}

	if (loop_port) {
		struct sa local;

		sa_set_in(&local, 0, loop_port);

		err = udp_listen(&turnc.loop_us, &local, udp_loop_recv, NULL);
		if (err) {
			DEBUG_WARNING("udp_listen: %m\n", err);
			goto out;
		}
		(void)re_printf("Local loop on port %u\n", loop_port);
	}

 out:
	return err;
}


void turn_start(const struct stun_conf *conf, int proto, const struct sa *srv,
		uint32_t lifetime)
{
	int err;

	if (turnc.tc)
		goto err;

	err = turnc_alloc(&turnc.tc, conf, proto, turnc.us, 0, srv,
			  turnc.username, turnc.password, lifetime,
			  turnc_handler, NULL);
	if (err) {
		DEBUG_WARNING("turnc_alloc: %s\n", err);
		goto err;
	}

	return;

 err:
	req.f.ar = false;
}


void turn_close(void)
{
	turnc.tc = mem_deref(turnc.tc);
	turnc.us = mem_deref(turnc.us);
	turnc.loop_us = mem_deref(turnc.loop_us);
}

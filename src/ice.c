/**
 * @file ice.c  ICE testing
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include "stunc.h"


#define DEBUG_MODULE "ice"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static struct {
	struct ice *ice;
	struct icem *icem;
	struct udp_sock *us;
} ice;


static bool if_handler(const char *ifname, const struct sa *sa, void *arg)
{
	(void)arg;

	/* Skip loopback and link-local addresses */
	if (sa_is_loopback(sa) || sa_is_linklocal(sa))
		return false;

	(void)re_printf("host candidate:    %10s   %j\n", ifname, sa);

	return 0 != icem_cand_add(ice.icem, 1, 0, ifname, sa);
}


static void ice_gather_handler(int err, uint16_t scode, const char *reason,
			       void *arg)
{
	(void)arg;

	if (err) {
		(void)re_fprintf(stderr, "gathering failed: %m\n", err);
		return;
	}

	(void)re_printf("gathering complete: %u %s\n", scode, reason);

	ice_test_debug();
}


int ice_test(const struct sa *stun_srv, int proto,
	     const char *username, const char *password)
{
	int err;

	err = ice_alloc(&ice.ice, ICE_MODE_FULL, true);
	if (err)
		return err;

	err = icem_alloc(&ice.icem, ice.ice, proto, 0,
			 ice_gather_handler, NULL, NULL);
	if (err)
		return err;

	err = udp_listen(&ice.us, NULL, NULL, NULL);
	if (err)
		return err;

	err = icem_comp_add(ice.icem, 1, ice.us);
	if (err)
		return err;

	if (net_if_apply(if_handler, NULL))
		return ENOMEM;

	if (username && password)
		err = icem_gather_relay(ice.icem, stun_srv,
					username, password);
	else
		err = icem_gather_srflx(ice.icem, stun_srv);
	if (err)
		return err;

	return 0;
}


void ice_close(void)
{
	ice.icem = mem_deref(ice.icem);
	ice.ice = mem_deref(ice.ice);
	ice.us = mem_deref(ice.us);
}


void ice_test_debug(void)
{
	(void)re_printf("----- ICE Session -----\n%H", ice_debug, ice.ice);
}

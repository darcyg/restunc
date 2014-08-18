/**
 * @file natbd.c  NAT Behaviour Discovery client
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include "stunc.h"


#define DEBUG_MODULE "natbd"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static struct {
	const struct sa *laddr;
	const struct sa *srv;
	int proto;
	const struct stun_conf *conf;
	struct nat_hairpinning *nh;
	struct nat_mapping *nm;
	struct nat_filtering *nf;
	struct nat_lifetime *nl;
	struct nat_genalg *ga;
} natbd;


/*
 * Diagnosing NAT Hairpinning
 */
static void nat_hairpinning_handler(int err, bool supported, void *arg)
{
	(void)arg;

	if (err) {
		(void)re_fprintf(stderr, "NAT Hairpinning failed: %m\n",
				 err);
	}
	else {
		(void)re_fprintf(stderr, "NAT Hairpinning: %sSupported\n",
				 supported ? "" : "NOT ");
	}

	req.f.nh = false;
	stunc_terminate_if_done();
}


void natbd_do_hairpinning(void)
{
	int err;

	if (natbd.nh) {
		DEBUG_WARNING("hairpinning detection in progress..\n");
		return;
	}

	err = nat_hairpinning_alloc(&natbd.nh, natbd.srv, natbd.proto,
				    natbd.conf, nat_hairpinning_handler, NULL);
	if (err) {
		DEBUG_WARNING("nat_hairpinning_alloc() failed (%m)\n", err);
		goto err;
	}

	err = nat_hairpinning_start(natbd.nh);
	if (err) {
		DEBUG_WARNING("nat_hairpinning_start() failed (%m)\n", err);
		goto err;
	}

	return;

 err:
	req.f.nh = false;
}


/*
 * Determining NAT Mapping Behavior
 */
static void nat_mapping_handler(int err, enum nat_type type, void *arg)
{
	(void)arg;

	if (err) {
		DEBUG_WARNING("NAT mapping failed (%m)\n", err);
	}
	else {
		(void)re_fprintf(stderr, "NAT Mapping: %s\n",
				 nat_type_str(type));
	}

	req.f.nm = false;
	stunc_terminate_if_done();
}


void natbd_do_mapping(void)
{
	int err;

	if (natbd.nm) {
		DEBUG_WARNING("NAT mapping detection in progress..");
		return;
	}

	err = nat_mapping_alloc(&natbd.nm, natbd.laddr,
				natbd.srv, natbd.proto,
				natbd.conf, nat_mapping_handler, NULL);
	if (err) {
		DEBUG_WARNING("nat_mapping_alloc() failed (%m)\n", err);
		goto err;
	}
	err = nat_mapping_start(natbd.nm);
	if (err) {
		DEBUG_WARNING("nat_mapping_start() failed (%m)\n", err);
		goto err;
	}

	return;

 err:
	req.f.nm = false;
}


/*
 * Determining NAT Filtering Behavior
 */
static void nat_filtering_handler(int err, enum nat_type type, void *arg)
{
	(void)arg;

	if (err) {
		DEBUG_WARNING("NAT filtering failed (%m)\n", err);
	}
	else {
		(void)re_fprintf(stderr, "NAT Filtering: %s\n",
				 nat_type_str(type));
	}

	req.f.nf = false;
	stunc_terminate_if_done();
}


void natbd_do_filtering(void)
{
	int err;

	if (natbd.nf) {
		DEBUG_WARNING("NAT filtering detection in progress..");
		return;
	}

	err = nat_filtering_alloc(&natbd.nf, natbd.srv,
				  natbd.conf, nat_filtering_handler, NULL);
	if (err) {
		DEBUG_WARNING("nat_filtering_alloc() failed (%m)\n", err);
		goto err;
	}

	err = nat_filtering_start(natbd.nf);
	if (err) {
		DEBUG_WARNING("nat_filtering_start() failed (%m)\n", err);
		goto err;
	}

	return;

 err:
	req.f.nf = false;
}


/* Binding Lifetime Discovery */
static void nat_lifetime_handler(int err,
				 const struct nat_lifetime_interval *interval,
				 void *arg)
{
	(void)arg;

	(void)re_fprintf(stderr, "NAT Lifetime: min=%u cur=%u max=%u\n",
			 interval->min, interval->cur, interval->max);

	if (err) {
		DEBUG_WARNING("nat_lifetime_handler: (%m)\n", err);
		req.f.nl = false;
		stunc_terminate_if_done();
	}

	/* terminate when values are stabilised.. */
	if (interval->min == interval->cur) {
		req.f.nl = false;
		stunc_terminate_if_done();
	}
}


void natbd_do_lifetime(void)
{
	int err;

	if (natbd.nl) {
		DEBUG_WARNING("NAT binding lifetime detection in progress..");
		return;
	}

	err = nat_lifetime_alloc(&natbd.nl, natbd.srv, 3,
				 natbd.conf, nat_lifetime_handler, NULL);
	if (err) {
		DEBUG_WARNING("nat_lifetime_alloc() failed (%m)\n", err);
		goto err;
	}

	err = nat_lifetime_start(natbd.nl);
	if (err) {
		DEBUG_WARNING("nat_lifetime_start() failed (%m)\n", err);
		goto err;
	}

	return;

 err:
	req.f.nl = false;
}


static void nat_genalg_handler(int err, uint16_t scode, const char *reason,
			       int status, const struct sa *map,
			       void *arg)
{
	(void)map;
	(void)arg;

	if (err) {
		DEBUG_WARNING("Generic ALG detection failed (%m)\n", err);
		goto out;
	}

	if (scode) {
		DEBUG_WARNING("Generic ALG detection failed: %u %s\n",
			      scode, reason);
		goto out;
	}

	(void)re_fprintf(stderr, "Generic ALG: %s Present\n",
			 1==status ? "" : "Not");

 out:

	req.f.ga = false;
	stunc_terminate_if_done();
}


void natbd_do_genalg(void)
{
	int err;

	if (natbd.ga)
		return;

	err = nat_genalg_alloc(&natbd.ga, natbd.srv, natbd.proto,
			       natbd.conf, nat_genalg_handler, NULL);
	if (err) {
		DEBUG_WARNING("nat_genalg_alloc: (%m)\n", err);
		goto err;
	}

	err = nat_genalg_start(natbd.ga);
	if (err) {
		DEBUG_WARNING("nat_genalg_start: (%m)\n", err);
		goto err;
	}

	return;

 err:
	req.f.ga = false;
}


void natbd_init(const struct sa *laddr, const struct sa *srv, int proto,
		const struct stun_conf *conf)
{
	natbd.laddr = laddr;
	natbd.srv   = srv;
	natbd.proto = proto;
	natbd.conf  = conf;
}


void natbd_close(void)
{
	natbd.nm = mem_deref(natbd.nm);
	natbd.nh = mem_deref(natbd.nh);
	natbd.nf = mem_deref(natbd.nf);
	natbd.nl = mem_deref(natbd.nl);
	natbd.ga = mem_deref(natbd.ga);
}

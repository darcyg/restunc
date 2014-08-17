/**
 * @file stunc.h  Interface to STUN client
 *
 * Copyright (C) 2010 Creytiv.com
 */


/*
 * ICE
 */

int  ice_test(const struct sa *stun_srv, int proto,
	      const char *username, const char *password);
void ice_close(void);
void ice_test_debug(void);


/*
 * Main
 */

union req {
	struct {
		bool bd;
		bool nh;
		bool nm;
		bool nf;
		bool nl;
		bool ga;
		bool ar;
		bool ice;
	} f;
	uint64_t flags;
};

extern union req req;


void terminate_if_done(void);


/*
 * NATBD
 */

void natbd_do_hairpinning(void);
void natbd_do_mapping(void);
void natbd_do_filtering(void);
void natbd_do_lifetime(void);
void natbd_do_genalg(void);

void natbd_init(const struct sa *laddr, const struct sa *srv, int proto,
		const struct stun_conf *conf);
void natbd_close(void);


/*
 * TURN
 */

int  turn_init(const char *username, const char *password,
	       const struct sa *peer, uint16_t loop_port);
void turn_start(const struct stun_conf *conf, int proto, const struct sa *srv,
		uint32_t lifetime);
void turn_close(void);

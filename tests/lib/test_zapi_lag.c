// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for the RFC 7130 micro-BFD ZAPI messages (lib/zclient.c).
 *
 * Copyright (C) 2026 Aviz Networks
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>

#include "lib/stream.h"
#include "lib/zclient.h"

static unsigned int checks;

#define CHECK(expr)                                                                               \
	do {                                                                                      \
		assert(expr);                                                                     \
		checks++;                                                                         \
	} while (0)

/* Check the header and leave the stream positioned at the body. */
static void check_header(struct stream *s, uint16_t cmd, vrf_id_t vrf_id, size_t body_len)
{
	struct zmsghdr hdr;

	stream_set_getp(s, 0);
	CHECK(zapi_parse_header(s, &hdr));
	CHECK(hdr.command == cmd);
	CHECK(hdr.vrf_id == vrf_id);
	CHECK(hdr.length == ZEBRA_HEADER_SIZE + body_len);
	CHECK(stream_get_endp(s) == ZEBRA_HEADER_SIZE + body_len);
}

/*
 * Decoding a truncated copy of the body must fail cleanly: nothing, one
 * byte, half, and all but the last byte.
 */
static void check_truncated(struct stream *s, size_t body_len,
			    int (*decode)(struct stream *s, void *out), void *out)
{
	size_t cuts[] = { 0, 1, body_len / 2, body_len - 1 };

	for (unsigned int i = 0; i < array_size(cuts); i++) {
		size_t cut = cuts[i];
		struct stream *t = stream_new(body_len);

		stream_put(t, STREAM_DATA(s) + ZEBRA_HEADER_SIZE, cut);
		CHECK(decode(t, out) == -1);
		stream_free(t);
	}
}

static int dec_reg(struct stream *s, void *o)
{
	return zapi_lag_register_decode(s, o);
}
static int dec_st(struct stream *s, void *o)
{
	return zapi_lag_bond_status_decode(s, o);
}
static int dec_mbr(struct stream *s, void *o)
{
	return zapi_lag_member_decode(s, o);
}
static int dec_dist(struct stream *s, void *o)
{
	return zapi_lag_dist_decode(s, o);
}

/* TC-1: REGISTER / UNREGISTER round trip, 5-byte body. */
static void test_register(void)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	struct zapi_lag_register in = { .bond_ifindex = 0x01020304,
					.flags = ZAPI_LAG_REG_F_FAIL_OPEN },
				 out;

	CHECK(zapi_lag_register_encode(s, ZEBRA_LAG_MBFD_REGISTER, 7, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_REGISTER, 7, 5);
	CHECK(zapi_lag_register_decode(s, &out) == 0);
	CHECK(out.bond_ifindex == in.bond_ifindex && out.flags == in.flags);
	check_truncated(s, 5, dec_reg, &out);

	CHECK(zapi_lag_register_encode(s, ZEBRA_LAG_MBFD_UNREGISTER, 0, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_UNREGISTER, 0, 5);
	stream_free(s);
}

/* TC-2: BOND_STATUS round trip, 7-byte body. */
static void test_bond_status(void)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	struct zapi_lag_bond_status in = { .bond_ifindex = 42,
					   .status = ZAPI_LAG_BOND_UNSUPPORTED_MODE,
					   .bond_mode = 1,
					   .member_count = 3 },
				    out;

	CHECK(zapi_lag_bond_status_encode(s, 3, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_BOND_STATUS, 3, 7);
	CHECK(zapi_lag_bond_status_decode(s, &out) == 0);
	CHECK(out.bond_ifindex == in.bond_ifindex && out.status == in.status &&
	      out.bond_mode == in.bond_mode && out.member_count == in.member_count);
	check_truncated(s, 7, dec_st, &out);
	stream_free(s);
}

/* TC-3: MEMBER_UPDATE round trip, 34-byte body; name always terminated. */
static void test_member(void)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	struct zapi_lag_member in = {
		.op = ZAPI_LAG_MBR_UPDATE,
		.bond_ifindex = 10,
		.mbr_ifindex = 11,
		.mac = { 0x02, 0, 0, 0xaa, 0xbb, 0x01 },
		.flags = ZAPI_LAG_MBR_F_KERNEL_ATTACHED | ZAPI_LAG_MBR_F_DISTRIBUTING |
			 ZAPI_LAG_MBR_F_EXT_REENSLAVED,
		.ad_actor_state = 0x3f,
	};
	struct zapi_lag_member out;

	strlcpy(in.mbr_name, "ens1f1", sizeof(in.mbr_name));
	CHECK(zapi_lag_member_encode(s, 0, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_MEMBER_UPDATE, 0, 34);
	CHECK(zapi_lag_member_decode(s, &out) == 0);
	CHECK(out.op == in.op && out.bond_ifindex == in.bond_ifindex &&
	      out.mbr_ifindex == in.mbr_ifindex && !strcmp(out.mbr_name, in.mbr_name) &&
	      !memcmp(out.mac, in.mac, ETH_ALEN) && out.flags == in.flags &&
	      out.ad_actor_state == in.ad_actor_state);
	check_truncated(s, 34, dec_mbr, &out);

	/* A name filling all IFNAMSIZ bytes comes back NUL-terminated. */
	memset(in.mbr_name, 'x', sizeof(in.mbr_name));
	CHECK(zapi_lag_member_encode(s, 0, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_MEMBER_UPDATE, 0, 34);
	CHECK(zapi_lag_member_decode(s, &out) == 0);
	CHECK(strlen(out.mbr_name) == IFNAMSIZ - 1);
	stream_free(s);
}

/* TC-4: DIST_SET round trip, 10-byte body. */
static void test_dist(void)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	struct zapi_lag_dist in = { .bond_ifindex = 5,
				    .mbr_ifindex = 6,
				    .enable = 1,
				    .flags = ZAPI_LAG_DIST_F_RESTORE_MAC },
			     out;

	CHECK(zapi_lag_dist_encode(s, 9, &in) == 0);
	check_header(s, ZEBRA_LAG_MBFD_DIST_SET, 9, 10);
	CHECK(zapi_lag_dist_decode(s, &out) == 0);
	CHECK(out.bond_ifindex == in.bond_ifindex && out.mbr_ifindex == in.mbr_ifindex &&
	      out.enable == in.enable && out.flags == in.flags);
	check_truncated(s, 10, dec_dist, &out);
	stream_free(s);
}

/* TC-5: string helpers. */
static void test_strings(void)
{
	char buf[128];

	CHECK(!strcmp(zapi_lag_bond_status2str(ZAPI_LAG_BOND_OK), "ok"));
	CHECK(!strcmp(zapi_lag_bond_status2str(ZAPI_LAG_BOND_EVPN_ES), "evpn-es"));
	CHECK(!strcmp(zapi_lag_bond_status2str(200), "unknown"));
	CHECK(!strcmp(zapi_lag_mbr_op2str(ZAPI_LAG_MBR_DEL), "delete"));
	CHECK(!strcmp(zapi_lag_mbr_op2str(0), "unknown"));

	CHECK(!strcmp(zapi_lag_mbr_flags2str(0, buf, sizeof(buf)), ""));
	CHECK(!strcmp(zapi_lag_mbr_flags2str(ZAPI_LAG_MBR_F_KERNEL_ATTACHED |
						     ZAPI_LAG_MBR_F_DISTRIBUTING,
					     buf, sizeof(buf)),
		      "attached,distributing"));

	/* Every buffer size: always terminated, never overrun. */
	for (size_t len = 1; len < sizeof(buf); len++) {
		char t[sizeof(buf) + 1];

		memset(t, 'X', sizeof(t));
		zapi_lag_mbr_flags2str(0x01ff, t, len);
		CHECK(strlen(t) < len);
		CHECK(t[len] == 'X');
	}
}

int main(void)
{
	test_register();
	test_bond_status();
	test_member();
	test_dist();
	test_strings();

	assert(checks > 0);
	puts("micro-BFD ZAPI message checks passed.");

	return 0;
}

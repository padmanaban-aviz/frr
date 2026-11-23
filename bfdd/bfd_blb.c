// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD over the bond (BLB) together with RFC 7130 micro-BFD.
 *
 * A BLB session is an ordinary single-hop BFD session (UDP 3784) on a bond,
 * usually protecting BGP. The kernel hashes its packets onto one member. If
 * that member fails silently, BLB loses its packets although the other
 * members work, and BGP goes down for a failure the bond survives. micro-BFD
 * holds the failed member down so the bond rehashes, but only in time if
 * BLB's detection time leaves room for it.
 *
 * "bundle coexistence bob-blb logical" (as in IOS XR) keeps BLB a session
 * of its own and checks, for every BLB session of a bond that has a "lag"
 * configuration, that
 *
 *   BLB detection >= micro-BFD detection + BFD_BLB_REHASH_MS + BLB interval
 *
 * that is, (BLB multiplier - 1) x BLB interval >= micro-BFD detection +
 * BFD_BLB_REHASH_MS, and warns (log, show, JSON) when it isn't. Nothing is
 * refused and no timer is changed, so existing configurations keep working.
 *
 * Why: BLB packets are lost from the silent failure until the bond sends on
 * another member, a window of micro-BFD detection plus the time the bond
 * takes to stop using the held member. BLB survives while fewer than its
 * multiplier packets in a row are lost, and depending on where its send
 * times fall that window costs up to window / interval + 1 packets.
 *
 * micro-BFD detection is the largest negotiated detection time over the
 * bond's Up micro-BFD sessions, or the configured one while none is Up. BLB
 * detection is the negotiated one while the session is Up (the echo
 * detection time if that is shorter) and the configured one while it isn't,
 * so a bad configuration is reported before it matters.
 *
 * The check runs on events (session up, down or renegotiated, configuration),
 * coalesced into one pass over all sessions BFD_BLB_CHECK_DELAY after the
 * first: a poll sequence moves the detection time through intermediate
 * values that would each be warned about otherwise.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>

#include "lib/json.h"
#include "lib/vrf.h"

#include "bfd.h"
#include "bfd_blb.h"
#include "bfd_lag.h"

static enum bfd_blb_mode blb_mode = BFD_BLB_MODE_NONE;
static struct event *t_blb_check;

#define BLB_DEBUG(fmt, ...)                                                                       \
	do {                                                                                      \
		if (bglobal.debug_lag)                                                            \
			zlog_debug("BLB: " fmt, ##__VA_ARGS__);                                   \
	} while (0)

const char *bfd_blb_mode2str(enum bfd_blb_mode mode)
{
	switch (mode) {
	case BFD_BLB_MODE_LOGICAL:
		return "logical";
	case BFD_BLB_MODE_NONE:
		break;
	}
	return "none";
}

enum bfd_blb_mode bfd_blb_get_mode(void)
{
	return blb_mode;
}

static const char *blb_peer_str(const struct bfd_session *bs, char *buf, size_t len)
{
	return inet_ntop(bs->key.family, &bs->key.peer, buf, len) ? buf : "?";
}

struct bfd_lag *bfd_blb_session_lag(const struct bfd_session *bs)
{
	struct bfd_lag *lag;

	if (bs->bfd_mode != BFD_MODE_TYPE_BFD || CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
		return NULL;
	if (!bs->key.ifname[0])
		return NULL;

	lag = bfd_lag_find(bs->key.ifname);
	if (!lag)
		return NULL;

	/* Same VRF as the bond. */
	if (strcmp(bs->key.vrfname[0] ? bs->key.vrfname : VRF_DEFAULT_NAME, bfd_lag_vrf_name(lag)))
		return NULL;

	return lag;
}

/*
 * micro-BFD detection of a bond (ms): the largest negotiated detection time
 * over its Up sessions; while none is Up, the largest configured one of its
 * sessions, or of its profile when no session runs (members held down or
 * not distributing run none, RFC 7130 Section 3). 0 if the bond has no
 * micro-BFD address family configured.
 */
static uint32_t blb_micro_detect_ms(const struct bfd_lag *lag)
{
	const struct bfd_lag_member *m = NULL;
	const struct bfd_profile *bp;
	uint32_t up_max = 0, cfg_max = 0;
	bool configured = false;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (lag->af[af].use && lag->af[af].has_dest)
			configured = true;
	if (!configured)
		return 0;

	while ((m = bfd_lag_member_next(lag, m))) {
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			const struct bfd_session *bs = bfd_lag_member_session(m, af);
			uint32_t d;

			if (!bs)
				continue;
			d = bs->detect_mult *
			    MAX(bs->timers.required_min_rx, bs->timers.desired_min_tx) / 1000;
			cfg_max = MAX(cfg_max, d);
			if (bs->ses_state == PTM_BFD_UP && bs->detect_TO)
				up_max = MAX(up_max, (uint32_t)(bs->detect_TO / 1000));
		}
	}
	if (up_max)
		return up_max;
	if (cfg_max)
		return cfg_max;

	bp = lag->profile_name ? bfd_profile_lookup(lag->profile_name) : NULL;
	if (bp)
		return bp->detection_multiplier * MAX(bp->min_rx, bp->min_tx) / 1000;
	return BFD_DEFDETECTMULT * MAX(BFD_DEFREQUIREDMINRX, BFD_DEFDESIREDMINTX) / 1000;
}

/*
 * BLB detection time and the interval of the packets it times (ms): the
 * negotiated ones while Up, the configured ones otherwise.
 */
struct blb_timing {
	uint32_t detect;
	uint32_t interval;
};

static struct blb_timing blb_timing(const struct bfd_session *bs)
{
	struct blb_timing t;

	if (bs->ses_state == PTM_BFD_UP && bs->detect_TO) {
		uint8_t mult = bs->remote_detect_mult ? bs->remote_detect_mult : bs->detect_mult;

		t.detect = bs->detect_TO / 1000;
		t.interval = mult ? t.detect / mult : t.detect;
	} else {
		t.detect = bs->detect_mult * bs->timers.required_min_rx / 1000;
		t.interval = bs->timers.required_min_rx / 1000;
	}

	/* Echo packets are hashed onto one member too. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO_ACTIVE) && bs->echo_detect_TO &&
	    bs->echo_detect_TO / 1000 < t.detect) {
		t.detect = bs->echo_detect_TO / 1000;
		t.interval = bs->echo_xmt_TO / 1000;
	}

	return t;
}

static uint32_t blb_need_ms(uint32_t micro, const struct blb_timing *t)
{
	return micro + BFD_BLB_REHASH_MS + t->interval;
}

static void blb_check_session(struct bfd_session *bs)
{
	struct bfd_blb_state *st = &bs->blb;
	struct bfd_lag *lag = NULL;
	uint32_t micro = 0, detect = 0, need = 0;
	struct blb_timing t = {};
	bool too_fast = false;
	char buf[INET6_ADDRSTRLEN];

	if (blb_mode == BFD_BLB_MODE_LOGICAL)
		lag = bfd_blb_session_lag(bs);
	if (lag)
		micro = blb_micro_detect_ms(lag);
	if (micro) {
		t = blb_timing(bs);
		detect = t.detect;
		need = blb_need_ms(micro, &t);
		too_fast = detect < need;
	}

	if (too_fast) {
		/* Once per change of the values. */
		if (!st->too_fast || st->detect_ms != detect || st->need_ms != need)
			zlog_warn("lag %s: BLB %s detection %u ms is below %u ms needed for micro-BFD %u ms, rehash %u ms and one %u ms interval (bundle coexistence bob-blb logical)",
				  lag->name, blb_peer_str(bs, buf, sizeof(buf)), detect, need,
				  micro, BFD_BLB_REHASH_MS, t.interval);
		st->too_fast = true;
		st->detect_ms = detect;
		st->need_ms = need;
		return;
	}

	if (st->too_fast) {
		if (lag && micro)
			zlog_notice("lag %s: BLB %s detection %u ms now meets the rule (needs %u ms)",
				    lag->name, blb_peer_str(bs, buf, sizeof(buf)), detect, need);
		else
			BLB_DEBUG("%s: no longer checked", blb_peer_str(bs, buf, sizeof(buf)));
	}
	memset(st, 0, sizeof(*st));
}

static void blb_check_iter(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;

	if (bs->bfd_mode == BFD_MODE_TYPE_BFD)
		blb_check_session(bs);
}

/* A bond with BLB sessions but no micro-BFD configured: say so once. */
struct blb_find_ctx {
	const struct bfd_lag *lag;
	bool found;
};

static void blb_lag_has_blb_iter(struct hash_bucket *hb, void *arg)
{
	struct blb_find_ctx *ctx = arg;

	if (!ctx->found && bfd_blb_session_lag(hb->data) == ctx->lag)
		ctx->found = true;
}

static bool blb_lag_has_blb(const struct bfd_lag *lag)
{
	struct blb_find_ctx ctx = { .lag = lag };

	bfd_key_iterate(blb_lag_has_blb_iter, &ctx);
	return ctx.found;
}

static void blb_check_lags(void)
{
	struct bfd_lag *lag;

	for (lag = (struct bfd_lag *)bfd_lag_next(NULL); lag;
	     lag = (struct bfd_lag *)bfd_lag_next(lag)) {
		bool warn = blb_mode == BFD_BLB_MODE_LOGICAL && !blb_micro_detect_ms(lag) &&
			    blb_lag_has_blb(lag);

		if (warn && !lag->blb_no_micro_warned)
			zlog_warn("lag %s: bundle coexistence set but no micro-BFD address family configured: BLB timers not checked",
				  lag->name);
		lag->blb_no_micro_warned = warn;
	}
}

static void blb_check_cb(struct event *t)
{
	bfd_key_iterate(blb_check_iter, NULL);
	blb_check_lags();
}

void bfd_blb_changed(void)
{
	/* Sessions freed on the way out need no check. */
	if (bglobal.bg_shutdown)
		return;

	/* Already pending: this event is covered by it. */
	event_add_timer_msec(master, blb_check_cb, NULL, BFD_BLB_CHECK_DELAY, &t_blb_check);
}

void bfd_blb_session_changed(const struct bfd_session *bs)
{
	/* A session with nothing to clear while the mode is off. */
	if (blb_mode == BFD_BLB_MODE_NONE && !bs->blb.too_fast)
		return;

	switch (bs->bfd_mode) {
	case BFD_MODE_TYPE_MICRO_BFD:
		bfd_blb_changed();
		break;
	case BFD_MODE_TYPE_BFD:
		if (bs->key.ifname[0] && !CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
			bfd_blb_changed();
		break;
	case BFD_MODE_TYPE_SBFD_ECHO:
	case BFD_MODE_TYPE_SBFD_INIT:
		break;
	}
}

void bfd_blb_set_mode(enum bfd_blb_mode mode)
{
	if (mode == blb_mode)
		return;

	blb_mode = mode;
	if (mode == BFD_BLB_MODE_NONE)
		zlog_notice(
			"bundle coexistence bob-blb removed: BLB sessions run as plain sessions");
	else
		zlog_warn("bundle coexistence bob-blb changed to %s: peers must use the same mode",
			  bfd_blb_mode2str(mode));
	bfd_blb_changed();
}

void bfd_blb_init(void)
{
	blb_mode = BFD_BLB_MODE_NONE;
}

void bfd_blb_terminate(void)
{
	event_cancel(&t_blb_check);
}

/*
 * Show.
 */
struct blb_show_ctx {
	const struct bfd_lag *lag;
	struct vty *vty;
	json_object *jsess;
	uint32_t micro;
};

static void blb_show_iter(struct hash_bucket *hb, void *arg)
{
	struct blb_show_ctx *ctx = arg;
	struct bfd_session *bs = hb->data;
	char buf[INET6_ADDRSTRLEN];
	struct blb_timing t;
	uint32_t need = 0;
	bool ok;

	if (bfd_blb_session_lag(bs) != ctx->lag)
		return;

	t = blb_timing(bs);
	if (ctx->micro)
		need = blb_need_ms(ctx->micro, &t);
	ok = !need || t.detect >= need;
	blb_peer_str(bs, buf, sizeof(buf));

	if (ctx->jsess) {
		json_object *js = json_object_new_object();

		json_object_string_add(js, "state", state_list[bs->ses_state].str);
		json_object_int_add(js, "detectionTime", t.detect);
		json_object_int_add(js, "interval", t.interval);
		json_object_int_add(js, "requiredDetectionTime", need);
		json_object_boolean_add(js, "ok", ok);
		json_object_object_add(ctx->jsess, buf, js);
	} else {
		if (need)
			vty_out(ctx->vty, "    %s: %s, detection %u ms, needs %u ms, %s\n", buf,
				state_list[bs->ses_state].str, t.detect, need,
				ok ? "ok" : "too fast");
		else
			vty_out(ctx->vty, "    %s: %s, detection %u ms\n", buf,
				state_list[bs->ses_state].str, t.detect);
	}
}

void bfd_blb_show_lag(struct vty *vty, const struct bfd_lag *lag, json_object *jl)
{
	struct blb_show_ctx ctx = { .lag = lag, .vty = vty };

	if (jl)
		json_object_string_add(jl, "blbMode", bfd_blb_mode2str(blb_mode));
	if (blb_mode == BFD_BLB_MODE_NONE)
		return;

	ctx.micro = blb_micro_detect_ms(lag);

	if (jl) {
		ctx.jsess = json_object_new_object();
		json_object_int_add(jl, "blbMicroDetectionTime", ctx.micro);
		json_object_int_add(jl, "blbRehashAllowance", BFD_BLB_REHASH_MS);
		bfd_key_iterate(blb_show_iter, &ctx);
		json_object_object_add(jl, "blbSessions", ctx.jsess);
		return;
	}

	if (ctx.micro)
		vty_out(vty,
			"  BLB coexistence: %s, micro-BFD detection %u ms, rehash allowance %u ms\n",
			bfd_blb_mode2str(blb_mode), ctx.micro, BFD_BLB_REHASH_MS);
	else
		vty_out(vty,
			"  BLB coexistence: %s, no micro-BFD address family configured: BLB timers not checked\n",
			bfd_blb_mode2str(blb_mode));
	bfd_key_iterate(blb_show_iter, &ctx);
}

void bfd_blb_show_peer(struct vty *vty, const struct bfd_session *bs, json_object *jo)
{
	const struct bfd_lag *lag;
	uint32_t micro, need = 0;
	struct blb_timing t;

	if (blb_mode == BFD_BLB_MODE_NONE)
		return;
	lag = bfd_blb_session_lag(bs);
	if (!lag)
		return;

	micro = blb_micro_detect_ms(lag);
	t = blb_timing(bs);
	if (micro)
		need = blb_need_ms(micro, &t);

	if (jo) {
		json_object *jb = json_object_new_object();

		json_object_string_add(jb, "lag", lag->name);
		json_object_string_add(jb, "mode", bfd_blb_mode2str(blb_mode));
		json_object_int_add(jb, "detectionTime", t.detect);
		json_object_int_add(jb, "interval", t.interval);
		json_object_int_add(jb, "requiredDetectionTime", need);
		json_object_boolean_add(jb, "ok", !need || t.detect >= need);
		json_object_object_add(jo, "blb", jb);
		return;
	}

	if (!need)
		vty_out(vty, "\t\tBLB: %s on lag %s, no micro-BFD address family configured\n",
			bfd_blb_mode2str(blb_mode), lag->name);
	else
		vty_out(vty, "\t\tBLB: %s on lag %s, detection %u ms, needs %u ms: %s\n",
			bfd_blb_mode2str(blb_mode), lag->name, t.detect, need,
			t.detect >= need ? "ok" : "too fast");
}

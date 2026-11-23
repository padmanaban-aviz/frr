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
 * "bundle coexistence bob-blb inherit" makes each BLB session a virtual
 * session: it keeps its discriminator and configuration, so clients
 * register, see and show it as before, but it sends no packets and runs no
 * timer (event.c and ptm_bfd_snd() skip it). Its state follows the bond's
 * aggregate of its address family: Up while at least min_links members
 * (at least one) are in and have their micro-BFD session Up, Down with
 * diag concatenated path down otherwise. A member failure is then handled
 * by micro-BFD alone and never reaches the clients; a bond failure does,
 * at micro-BFD speed. Both ends must run inherit: a control packet on UDP
 * 3784 for a virtual session means the peer runs a real BLB session, and
 * is counted and reported as a peer mismatch, not answered.
 *
 * Inherited states change on the next event loop pass after the event (no
 * extra delay; micro-BFD detection and hold-down already damp flapping),
 * outside of the session code that reported it.
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
static struct event *t_blb_inherit;

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
	case BFD_BLB_MODE_INHERIT:
		return "inherit";
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
	st->too_fast = false;
	st->detect_ms = 0;
	st->need_ms = 0;
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
		bool warn = blb_mode != BFD_BLB_MODE_NONE && !blb_micro_detect_ms(lag) &&
			    blb_lag_has_blb(lag);

		if (warn && !lag->blb_no_micro_warned)
			zlog_warn("lag %s: bundle coexistence set but no micro-BFD address family configured: %s",
				  lag->name,
				  blb_mode == BFD_BLB_MODE_INHERIT ? "BLB sessions stay down"
								   : "BLB timers not checked");
		lag->blb_no_micro_warned = warn;
	}
}

static void blb_check_cb(struct event *t)
{
	bfd_key_iterate(blb_check_iter, NULL);
	blb_check_lags();
}

/*
 * Inherit mode.
 */

/* The family whose micro-BFD sessions a BLB session follows. */
static enum bfd_lag_af blb_session_af(const struct bfd_lag *lag, const struct bfd_session *bs)
{
	enum bfd_lag_af af = CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6) ? BFD_LAG_AF_IPV6
								       : BFD_LAG_AF_IPV4;
	enum bfd_lag_af other = af == BFD_LAG_AF_IPV4 ? BFD_LAG_AF_IPV6 : BFD_LAG_AF_IPV4;

	/* micro-BFD in one family only: both follow it. */
	if (!(lag->af[af].use && lag->af[af].has_dest) && lag->af[other].use &&
	    lag->af[other].has_dest)
		return other;
	return af;
}

static uint32_t blb_min_links(const struct bfd_lag *lag)
{
	return MAX(lag->min_links, 1);
}

/*
 * Members of the aggregate: in the bond (not held down by micro-BFD),
 * distributing or standby, with their micro-BFD session of the family Up.
 */
static uint32_t blb_aggregate(const struct bfd_lag *lag, enum bfd_lag_af af, uint32_t *members)
{
	const struct bfd_lag_member *m = NULL;
	uint32_t up = 0, total = 0;

	if (!lag->af[af].use || !lag->af[af].has_dest) {
		if (members)
			*members = 0;
		return 0;
	}

	while ((m = bfd_lag_member_next(lag, m))) {
		const struct bfd_session *ms = bfd_lag_member_session(m, af);

		total++;
		if (bfd_lag_member_detached(m))
			continue;
		if (!bfd_lag_member_distributing(m) && !bfd_lag_member_standby(m))
			continue;
		if (ms && ms->ses_state == PTM_BFD_UP)
			up++;
	}
	if (members)
		*members = total;
	return up;
}

static bool blb_mismatch_active(const struct bfd_session *bs)
{
	struct timeval now;

	if (!bs->blb.mismatch_pkts)
		return false;
	monotime(&now);
	return now.tv_sec - bs->blb.mismatch_last.tv_sec < BFD_BLB_MISMATCH_CLEAR;
}

static void blb_make_virtual(struct bfd_session *bs)
{
	char buf[INET6_ADDRSTRLEN];

	bs->blb.virt = true;
	bs->blb.mismatch_pkts = 0;
	bfd_recvtimer_delete(bs);
	bfd_xmttimer_delete(bs);
	ptm_bfd_echo_stop(bs);
	bs->polling = 0;
	if (bs->ses_state != PTM_BFD_UP && bs->ses_state != PTM_BFD_ADM_DOWN)
		bs->local_diag = BD_CONCATPATH_DOWN;
	BLB_DEBUG("%s: virtual (inherit), no packets", blb_peer_str(bs, buf, sizeof(buf)));
}

static void blb_make_real(struct bfd_session *bs)
{
	char buf[INET6_ADDRSTRLEN];

	bs->blb.virt = false;
	bs->blb.mismatch_pkts = 0;
	BLB_DEBUG("%s: real session again", blb_peer_str(bs, buf, sizeof(buf)));

	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->ses_state == PTM_BFD_ADM_DOWN)
		return;

	/* Start over as a real session: Down, then the three-way handshake. */
	if (bs->ses_state != PTM_BFD_DOWN)
		ptm_bfd_sess_dn(bs, BD_PATH_DOWN, false);
	else
		bs_set_slow_timers(bs);

	if (!CHECK_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE)) {
		bfd_recvtimer_update(bs);
		ptm_bfd_start_xmt_timer(bs, false);
	}
}

/* Make the session virtual or real as the mode wants, set its state. */
static void blb_inherit_sync(struct bfd_session *bs)
{
	struct bfd_lag *lag = NULL;
	enum bfd_lag_af af;
	uint32_t up, members, need;
	char buf[INET6_ADDRSTRLEN];

	if (blb_mode == BFD_BLB_MODE_INHERIT && bs->sock != -1 && !bs->bdc)
		lag = bfd_blb_session_lag(bs);

	if (lag && !bs->blb.virt)
		blb_make_virtual(bs);
	else if (!lag && bs->blb.virt)
		blb_make_real(bs);
	if (!bs->blb.virt)
		return;

	/* Configuration changes may have asked for a poll: nothing is sent. */
	bs->polling = 0;

	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->ses_state == PTM_BFD_ADM_DOWN)
		return;

	af = blb_session_af(lag, bs);
	up = blb_aggregate(lag, af, &members);
	need = blb_min_links(lag);

	if (up >= need && bs->ses_state != PTM_BFD_UP) {
		zlog_notice("lag %s: BLB %s inherited up (%s %u of %u members, min_links %u)",
			    lag->name, blb_peer_str(bs, buf, sizeof(buf)),
			    af == BFD_LAG_AF_IPV4 ? "IPv4" : "IPv6", up, members, need);
		ptm_bfd_sess_up(bs);
		bs->polling = 0;
	} else if (up < need && bs->ses_state != PTM_BFD_DOWN) {
		if (bs->ses_state == PTM_BFD_UP)
			zlog_warn("lag %s: BLB %s inherited down (%s %u of %u members, min_links %u)",
				  lag->name, blb_peer_str(bs, buf, sizeof(buf)),
				  af == BFD_LAG_AF_IPV4 ? "IPv4" : "IPv6", up, members, need);
		ptm_bfd_sess_dn(bs, BD_CONCATPATH_DOWN, false);
	}
}

static void blb_inherit_iter(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;

	if (bs->bfd_mode == BFD_MODE_TYPE_BFD)
		blb_inherit_sync(bs);
}

static void blb_inherit_cb(struct event *t)
{
	bfd_key_iterate(blb_inherit_iter, NULL);
}

static void blb_inherit_schedule(void)
{
	if (bglobal.bg_shutdown)
		return;
	event_add_event(master, blb_inherit_cb, NULL, 0, &t_blb_inherit);
}

void bfd_blb_rx_virtual(struct bfd_session *bs)
{
	char buf[INET6_ADDRSTRLEN];
	struct bfd_lag *lag = bfd_blb_session_lag(bs);

	/* Logged when the mark is set, again after it cleared. */
	if (!blb_mismatch_active(bs))
		zlog_warn("lag %s: BLB peer %s sends BFD on 3784, inherit mode needs inherit on the peer",
			  lag ? lag->name : "?", blb_peer_str(bs, buf, sizeof(buf)));
	bs->blb.mismatch_pkts++;
	monotime(&bs->blb.mismatch_last);
}

void bfd_blb_changed(void)
{
	/* Sessions freed on the way out need no check. */
	if (bglobal.bg_shutdown)
		return;

	if (blb_mode == BFD_BLB_MODE_INHERIT)
		blb_inherit_schedule();

	/* Already pending: this event is covered by it. */
	event_add_timer_msec(master, blb_check_cb, NULL, BFD_BLB_CHECK_DELAY, &t_blb_check);
}

void bfd_blb_session_changed(const struct bfd_session *bs)
{
	/* A session with nothing to clear while the mode is off. */
	if (blb_mode == BFD_BLB_MODE_NONE && !bs->blb.too_fast && !bs->blb.virt)
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
	/* Sessions become virtual, or real again. */
	blb_inherit_schedule();
	bfd_blb_changed();
}

void bfd_blb_init(void)
{
	blb_mode = BFD_BLB_MODE_NONE;
}

void bfd_blb_terminate(void)
{
	event_cancel(&t_blb_check);
	event_cancel(&t_blb_inherit);
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

static void blb_show_inherit_session(struct blb_show_ctx *ctx, const struct bfd_session *bs)
{
	char buf[INET6_ADDRSTRLEN];
	enum bfd_lag_af af = blb_session_af(ctx->lag, bs);
	bool mismatch = blb_mismatch_active(bs);

	blb_peer_str(bs, buf, sizeof(buf));
	if (ctx->jsess) {
		json_object *js = json_object_new_object();

		json_object_string_add(js, "state", state_list[bs->ses_state].str);
		json_object_boolean_add(js, "virtual", bs->blb.virt);
		json_object_string_add(js, "follows", af == BFD_LAG_AF_IPV4 ? "ipv4" : "ipv6");
		json_object_boolean_add(js, "peerMismatch", mismatch);
		json_object_int_add(js, "mismatchPackets", bs->blb.mismatch_pkts);
		json_object_object_add(ctx->jsess, buf, js);
		return;
	}
	vty_out(ctx->vty, "    %s: %s, %s, follows %s%s\n", buf, state_list[bs->ses_state].str,
		bs->blb.virt ? "inherited (virtual, no packets)"
			     : "not virtual (bond or socket not ready)",
		af == BFD_LAG_AF_IPV4 ? "IPv4" : "IPv6",
		mismatch ? ", PEER MISMATCH: peer sends BFD on 3784" : "");
}

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

	if (blb_mode == BFD_BLB_MODE_INHERIT) {
		blb_show_inherit_session(ctx, bs);
		return;
	}

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

	if (blb_mode == BFD_BLB_MODE_INHERIT) {
		uint32_t up[BFD_LAG_AF_MAX], members[BFD_LAG_AF_MAX];

		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
			up[af] = blb_aggregate(lag, af, &members[af]);

		if (jl) {
			json_object *ja = json_object_new_object();

			json_object_int_add(jl, "minLinks", lag->min_links);
			for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
				json_object *jf;

				if (!lag->af[af].use || !lag->af[af].has_dest)
					continue;
				jf = json_object_new_object();
				json_object_string_add(jf, "state",
						       up[af] >= blb_min_links(lag) ? "up"
										    : "down");
				json_object_int_add(jf, "membersUp", up[af]);
				json_object_int_add(jf, "members", members[af]);
				json_object_object_add(ja, af == BFD_LAG_AF_IPV4 ? "ipv4" : "ipv6",
						       jf);
			}
			json_object_object_add(jl, "blbAggregate", ja);
			ctx.jsess = json_object_new_object();
			bfd_key_iterate(blb_show_iter, &ctx);
			json_object_object_add(jl, "blbSessions", ctx.jsess);
			return;
		}

		vty_out(vty, "  BLB coexistence: inherit, min_links %u", blb_min_links(lag));
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
			if (lag->af[af].use && lag->af[af].has_dest)
				vty_out(vty, ", %s %s (%u of %u members)",
					af == BFD_LAG_AF_IPV4 ? "IPv4" : "IPv6",
					up[af] >= blb_min_links(lag) ? "up" : "down", up[af],
					members[af]);
		if (!blb_micro_detect_ms(lag))
			vty_out(vty, ", no micro-BFD address family configured: BLB stays down");
		vty_out(vty, "\n");
		bfd_key_iterate(blb_show_iter, &ctx);
		return;
	}

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

	if (blb_mode == BFD_BLB_MODE_INHERIT) {
		enum bfd_lag_af af = blb_session_af(lag, bs);
		uint32_t members, up = blb_aggregate(lag, af, &members);
		bool mismatch = blb_mismatch_active(bs);

		if (jo) {
			json_object *jb = json_object_new_object();

			json_object_string_add(jb, "lag", lag->name);
			json_object_string_add(jb, "mode", bfd_blb_mode2str(blb_mode));
			json_object_boolean_add(jb, "virtual", bs->blb.virt);
			json_object_string_add(jb, "follows",
					       af == BFD_LAG_AF_IPV4 ? "ipv4" : "ipv6");
			json_object_int_add(jb, "membersUp", up);
			json_object_int_add(jb, "minLinks", blb_min_links(lag));
			json_object_boolean_add(jb, "peerMismatch", mismatch);
			json_object_int_add(jb, "mismatchPackets", bs->blb.mismatch_pkts);
			json_object_object_add(jo, "blb", jb);
			return;
		}
		vty_out(vty,
			"\t\tBLB: inherited from lag %s (%s, %s %u of %u members Up, min_links %u)\n",
			lag->name, bs->blb.virt ? "virtual, no packets" : "not virtual yet",
			af == BFD_LAG_AF_IPV4 ? "IPv4" : "IPv6", up, members, blb_min_links(lag));
		if (mismatch)
			vty_out(vty,
				"\t\tBLB: PEER MISMATCH, %" PRIu64
				" packets on 3784: the peer must run inherit too\n",
				bs->blb.mismatch_pkts);
		return;
	}

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

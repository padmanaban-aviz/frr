// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD raw frame builder and parser.
 *
 * Builds a complete Ethernet + IPv4/IPv6 + UDP frame around a BFD payload,
 * for the packet paths that send through a raw (AF_PACKET) socket instead of
 * a UDP socket, and takes such a frame apart again on receive.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#ifndef _BFD_FRAME_H_
#define _BFD_FRAME_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Length of an Ethernet MAC address. */
#define BFD_FRAME_MAC_LEN 6

/** Ethernet header length (no VLAN tag). */
#define BFD_FRAME_ETH_HLEN 14

/** Largest header overhead the builder adds (Ethernet + IPv6 + UDP). */
#define BFD_FRAME_MAX_HLEN (BFD_FRAME_ETH_HLEN + 40 + 8)

struct bfd_frame_params {
	/** AF_INET or AF_INET6. */
	int family;

	/** Ethernet source and destination MAC addresses. */
	uint8_t smac[BFD_FRAME_MAC_LEN];
	uint8_t dmac[BFD_FRAME_MAC_LEN];

	/** IP source and destination addresses (only the family's member is used). */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src, dst;

	/** UDP source and destination ports, host byte order. */
	uint16_t sport;
	uint16_t dport;

	/** IPv4 TTL or IPv6 hop limit. */
	uint8_t ttl;

	/** IPv4 TOS byte or IPv6 traffic class. */
	uint8_t tos;

	/** IPv4 identification field, host byte order (ignored for IPv6). */
	uint16_t ip_id;
};

/**
 * Build an Ethernet + IP + UDP frame carrying `payload`.
 *
 * Fills in the IPv4 header checksum and the UDP checksum (computed over the
 * IPv4 or IPv6 pseudo header; never left zero for IPv6, as RFC 8200
 * requires).
 *
 * \param buf output buffer.
 * \param buflen size of `buf`.
 * \param params frame parameters.
 * \param payload UDP payload (BFD control or echo packet).
 * \param plen payload length.
 *
 * \returns total frame length, or -1 when the family is not supported, the
 * buffer is too small or the payload does not fit in a UDP datagram.
 */
ssize_t bfd_frame_build(uint8_t *buf, size_t buflen, const struct bfd_frame_params *params,
			const void *payload, size_t plen);

/** A received frame, as taken apart by bfd_frame_parse(). */
struct bfd_frame_info {
	/** AF_INET or AF_INET6. */
	int family;

	/** Ethernet source and destination MAC addresses. */
	uint8_t smac[BFD_FRAME_MAC_LEN];
	uint8_t dmac[BFD_FRAME_MAC_LEN];

	/** IP source and destination addresses. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src, dst;

	/** UDP source and destination ports, host byte order. */
	uint16_t sport;
	uint16_t dport;

	/** IPv4 TTL or IPv6 hop limit. */
	uint8_t ttl;

	/** UDP payload, pointing into the parsed buffer. */
	const uint8_t *payload;
	size_t plen;
};

/** bfd_frame_parse() results. */
enum bfd_frame_parse_result {
	BFD_FRAME_OK = 0,
	/** Shorter than the headers it announces. */
	BFD_FRAME_ESHORT = -1,
	/** Not untagged IPv4 or IPv6 (VLAN tags included). */
	BFD_FRAME_ENOTIP = -2,
	/** Not UDP (IPv6: UDP not the first next header). */
	BFD_FRAME_ENOTUDP = -3,
	/** IPv4 fragment. */
	BFD_FRAME_EFRAG = -4,
	/** Inconsistent IP or UDP length, or bad IPv4 header. */
	BFD_FRAME_EBADHDR = -5,
	/** Wrong IPv4 header checksum. */
	BFD_FRAME_ECKSUM = -6,
};

/**
 * Take apart an Ethernet + IPv4/IPv6 + UDP frame, as bfd_frame_build()
 * builds it.
 *
 * The IPv4 header checksum is verified. The UDP checksum is not: a frame
 * read from a raw socket may carry a checksum the sending host left to the
 * NIC, and the BFD payload is validated on its own anyway. Ethernet padding
 * after the IP packet is ignored.
 *
 * \param buf the frame, starting with the Ethernet header.
 * \param len frame length.
 * \param info filled in on success.
 *
 * \returns BFD_FRAME_OK or a negative enum bfd_frame_parse_result.
 */
int bfd_frame_parse(const uint8_t *buf, size_t len, struct bfd_frame_info *info);

/** Text for a bfd_frame_parse() result. */
const char *bfd_frame_parse_strerror(int result);

#ifdef __cplusplus
}
#endif

#endif /* _BFD_FRAME_H_ */

/* 这些都是在busybox 中udhcp 模块有原函数可以借鉴
 * socket和包的filter参照wirelshark抓的包分析比较清晰。
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
static int udhcp_raw_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	log2("opening raw socket on ifindex %d", ifindex);

	fd = xsocket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	/* ^^^^^
	 * SOCK_DGRAM: remove link-layer headers on input (SOCK_RAW keeps them)
	 * ETH_P_IP: want to receive only packets with IPv4 eth type
	 */
	log3("got raw socket fd %d", fd);

	memset(&sock, 0, sizeof(sock)); /* let's be deterministic */
	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IP);
	sock.sll_ifindex = ifindex;
	/*sock.sll_hatype = ARPHRD_???;*/
	/*sock.sll_pkttype = PACKET_???;*/
	/*sock.sll_halen = ???;*/
	/*sock.sll_addr[8] = ???;*/
	xbind(fd, (struct sockaddr *) &sock, sizeof(sock));
	
	/* 这个filter是BPF的一些define，网上可以搜到
	 * 和 tcpdump -dd udp src port 68, tcpdump可以显示这些规则，但是有些区别
	 */
#if 0 /* Several users reported breakage when BPF filter is used */
	if (CLIENT_PORT == 68) {
		/* Use only if standard port is in use */
		/*
		 *	I've selected not to see LL header, so BPF doesn't see it, too.
		 *	The filter may also pass non-IP and non-ARP packets, but we do
		 *	a more complete check when receiving the message in userspace.
		 *
		 * and filter shamelessly stolen from:
		 *
		 *	http://www.flamewarmaster.de/software/dhcpclient/
		 *
		 * There are a few other interesting ideas on that page (look under
		 * "Motivation").  Use of netlink events is most interesting.  Think
		 * of various network servers listening for events and reconfiguring.
		 * That would obsolete sending HUP signals and/or make use of restarts.
		 *
		 * Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
		 * License: GPL v2.
		 */
		static const struct sock_filter filter_instr[] = {
			/* load 9th byte (protocol) */
			BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
			/* jump to L1 if it is IPPROTO_UDP, else to L4 */
			BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 0, 6),
			/* L1: load halfword from offset 6 (flags and frag offset) */
			BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 6),
			/* jump to L4 if any bits in frag offset field are set, else to L2 */
			BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x1fff, 4, 0),
			/* L2: skip IP header (load index reg with header len) */
			BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0),
			/* load udp destination port from halfword[header_len + 2] */
			BPF_STMT(BPF_LD|BPF_H|BPF_IND, 2),
			/* jump to L3 if udp dport is CLIENT_PORT, else to L4 */
			BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 68, 0, 1),
			/* L3: accept packet ("accept 0x7fffffff bytes") */
			/* Accepting 0xffffffff works too but kernel 2.6.19 is buggy */
			BPF_STMT(BPF_RET|BPF_K, 0x7fffffff),
			/* L4: discard packet ("accept zero bytes") */
			BPF_STMT(BPF_RET|BPF_K, 0),
		};
		static const struct sock_fprog filter_prog = {
			.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
			/* casting const away: */
			.filter = (struct sock_filter *) filter_instr,
		};
		/* Ignoring error (kernel may lack support for this) */
		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
				sizeof(filter_prog)) >= 0)
			log1("attached filter to raw socket fd"); // log?
	}
#endif

	if (setsockopt_1(fd, SOL_PACKET, PACKET_AUXDATA) != 0) {
		if (errno != ENOPROTOOPT)
			log1("can't set PACKET_AUXDATA on raw socket");
	}

	log1("created raw socket");

	return fd;
}

/* Get an option with bounds checking (warning, result is not aligned) */
uint8_t* get_option(struct dhcp_packet *packet, int code)
{
	uint8_t *optionptr;
	int len;
	int rem;
	int overload = 0;
	enum {
		FILE_FIELD101  = FILE_FIELD  * 0x101,
		SNAME_FIELD101 = SNAME_FIELD * 0x101,
	};

	/* option bytes: [code][len][data1][data2]..[dataLEN] */
	optionptr = packet->options;
	rem = sizeof(packet->options);
	while (1) {
		if (rem <= 0) {
 complain:
			bb_error_msg("bad packet, malformed option field");
			return NULL;
		}

		/* DHCP_PADDING and DHCP_END have no [len] byte */
		if (optionptr[OPT_CODE] == DHCP_PADDING) {
			rem--;
			optionptr++;
			continue;
		}
		if (optionptr[OPT_CODE] == DHCP_END) {
			if ((overload & FILE_FIELD101) == FILE_FIELD) {
				/* can use packet->file, and didn't look at it yet */
				overload |= FILE_FIELD101; /* "we looked at it" */
				optionptr = packet->file;
				rem = sizeof(packet->file);
				continue;
			}
			if ((overload & SNAME_FIELD101) == SNAME_FIELD) {
				/* can use packet->sname, and didn't look at it yet */
				overload |= SNAME_FIELD101; /* "we looked at it" */
				optionptr = packet->sname;
				rem = sizeof(packet->sname);
				continue;
			}
			break;
		}

		if (rem <= OPT_LEN)
			goto complain; /* complain and return NULL */
		len = 2 + optionptr[OPT_LEN];
		rem -= len;
		if (rem < 0)
			goto complain; /* complain and return NULL */

		if (optionptr[OPT_CODE] == code) {
			if (optionptr[OPT_LEN] == 0) {
				/* So far no valid option with length 0 known.
				 * Having this check means that searching
				 * for DHCP_MESSAGE_TYPE need not worry
				 * that returned pointer might be unsafe
				 * to dereference.
				 */
				goto complain; /* complain and return NULL */
			}
			log_option("option found", optionptr);
			return optionptr + OPT_DATA;
		}

		if (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD) {
			if (len >= 3)
				overload |= optionptr[OPT_DATA];
			/* fall through */
		}
		optionptr += len;
	}

	/* log3 because udhcpc uses it a lot - very noisy */
	log3("option 0x%02x not found", code);
	return NULL;
}

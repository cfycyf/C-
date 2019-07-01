/* select 用法:
 * int select(int nfds, fd_set *readfds, fd_set *writefd, fd_set *exceptfds, struct timeval *utimeout);
 * readfds, writefds, exceptfds为所要监听的三个描述符集：
 * ——readfds 监听文件描述符是否可读，不监听可以传入 NULL
 * ——writefds 监听文件描述符是否可写 ，不监听可以传入 NULL
 * ——exceptfds 监听文件描述符是否有异常，不监听可以传入 NULL
 * nfds 是 select() 监听的三个描述符集中描述符的最大值+1
 * timeout 设置超时时间 
 * 1. nfds必须被正确设置，一般取描述符集中描述符的最大值并加1。
 * 2. 在非必须的情况下，尽量使用不超时的select()，即将utimeout参数设置为NULL。
 * 3. timeout的值必须在每次select()之前重新赋值，因为操作系统会修改此值。
 *		while(1) {
 *		    timeout.tv_sec = 1;
 *			timeout.tv_usec = 0;
 *		    select(nfds, &readfds, &writefds, &exceptfds, &timeout);
 *		}
 *	4. 由于select()会修改字符集，因此如果select()调用是在一个循环中，则描述符集必须被重新赋值。
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <sys/sysinfo.h>


static int raw_fd = -1;
static int signal_pipe[2];
int cur_pos=0;
struct caped_info_t caped_info_list[MAX_DHCP_MSG]={0};
struct cap_config_t cap_config = {
	/* Default options. */
	interface: "eth0",
	ifindex: 0,
	arp: "\0\0\0\0\0\0",		/* appease gcc-3.0 */
};

/* Signal handler */
static void signal_handler(int sig)
{
	if (send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT) < 0) {
		LOG(LOG_ERR, "Could not send signal: %s",
			strerror(errno));
	}
}

int main(int argc, char *argv[])
{
	unsigned char *message;
	int len, sig, retval, max_fd;
	fd_set rfds;
	struct timeval tv;
	struct dhcpMessage packet;

	/* setup signal handlers */
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);
	signal(SIGUSR1, signal_handler);
	
	if (read_interface("br0", &cap_config.ifindex,NULL, cap_config.arp) < 0){
		LOG(LOG_ERR, "FATAL: couldn't read the interface.");
		return 0;
	}
	
	for (;;) {
		FD_ZERO(&rfds);
		/* set raw_server */
		if(raw_fd < 0){
			if((raw_fd = raw_socket(cap_config.ifindex, SERVER_PORT)) < 0){
				LOG(LOG_ERR, "FATAL: couldn't create raw server socket, %s", strerror(errno));
				return 0;
			}
		}

		if (raw_fd >= 0) FD_SET(raw_fd, &rfds);
		FD_SET(signal_pipe[0], &rfds);

		/* timeout interval 0.5s */
		tv.tv_sec = 0;
		tv.tv_usec = 500000;
		/* select for non blocking */
		max_fd = signal_pipe[0] > raw_fd ? signal_pipe[0] : raw_fd;
		retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);
		if(retval <= 0){
			DEBUG(LOG_ERR, "select no file for read or listening");
			continue;
		}

		if(FD_ISSET(raw_fd, &rfds)){
			if((len = get_raw_packet(&packet, raw_fd)) < 0)
				continue;
			if ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
				DEBUG(LOG_ERR, "couldnt get option from packet -- ignoring");
				continue;
			}

			if(*message == DHCPREQUEST){
						/* dhcp data options format */
						/* |ID|length| data |   */
						/*           ^     */
				/* get_option return *pos */
				/*  mac->data |hardeare type| macaddr| */
				DEBUG(LOG_INFO, "get the DHCPREQUEST packet");
				char *host_name = get_option(&packet, DHCP_HOST_NAME);
				char *srcmac = get_option(&packet, DHCP_CLIENT_ID);
				if(host_name && srcmac){
					if(check_matched_mac(srcmac))
						add_to_info_list(host_name, srcmac);
				}
			}
			else{
				DEBUG(LOG_INFO, "useless  packet, keep listening");
				continue;
			}
		}
		
		if(FD_ISSET(signal_pipe[0], &rfds)){	
			if (read(signal_pipe[0], &sig, sizeof(sig)) < 0) { 
				DEBUG(LOG_ERR, "Could not read signal: %s", strerror(errno));
				continue; /* probably just EINTR */
			}

			switch (sig) {
				case SIGUSR1:
					dump_caped_info_list(DUMP_FILE);
					break;
			}
		}
	}

	return 0;
}

void dump_caped_info_list(char *dump_file)
{
	int i=0;
	FILE *fp;
	char mac2s[18]={0};
	if((fp=fopen(dump_file, "w")) == NULL){
		DEBUG(LOG_ERR, "Open dump file(%s) failed",dump_file);
		return;
	}
	else{
		for(i=0;i<MAX_DHCP_MSG && caped_info_list[i].hostName !=NULL;i++){
			memset(mac2s, 0, sizeof(mac2s));
			sprintf(mac2s,"%02x:%02x:%02x:%02x:%02x:%02x\n",
					caped_info_list[i].mac[0],caped_info_list[i].mac[1],caped_info_list[i].mac[2],
					caped_info_list[i].mac[3],caped_info_list[i].mac[4],caped_info_list[i].mac[5]);
			fwrite(caped_info_list[i].hostName, strlen(caped_info_list[i].hostName), 1,fp);
			fwrite(",", 1, 1,fp);
			fwrite(mac2s, sizeof(mac2s), 1,fp);
		}
		fclose(fp);
	}
	return;
}

int check_matched_mac(u_int8_t *mac)
{
	int i=0, j, count;
	while(caped_info_list[i].hostName != NULL && i < MAX_DHCP_MSG){
		count = 0;
		for(j=0;j < 6; j++){
			if(caped_info_list[i].mac[j] == mac[j+1]){
				count++;
			}
		}
		if(count == 6){
			DEBUG(LOG_INFO, "The mac(%02x:%02x:%02x:%02x:%02x:%02x) had already record", mac[1],mac[2],mac[3],mac[4],mac[5],mac[6]);
			return 0;
		}
		i++;
	}
	DEBUG(LOG_INFO, "The mac(%02x:%02x:%02x:%02x:%02x:%02x) is a new device", mac[1],mac[2],mac[3],mac[4],mac[5],mac[6]);
	return 1;
}

void add_to_info_list(char *name, u_int8_t *mac)
{
	int i;
	if(caped_info_list[cur_pos].hostName != NULL){
		free(caped_info_list[cur_pos].hostName);
	}
	caped_info_list[cur_pos].hostName = (char*)malloc(sizeof(char)*name[-1] +1);
	strncpy(caped_info_list[cur_pos].hostName, name, name[-1]);
	caped_info_list[cur_pos].hostName[name[-1]] = '\0';
	for(i=0; i<6;i++)
		caped_info_list[cur_pos].mac[i]=mac[i+1];
	cur_pos = (cur_pos +1)%MAX_DHCP_MSG;
	
	return;
}

/* return -1 on errors that are fatal for the socket, -2 for those that aren't */
int get_raw_packet(struct dhcpMessage *payload, int fd)
{
	int bytes;
	struct udp_dhcp_packet packet;
	u_int32_t source, dest;
	u_int16_t check;

	memset(&packet, 0, sizeof(struct udp_dhcp_packet));
	bytes = read(fd, &packet, sizeof(struct udp_dhcp_packet));
	if (bytes < 0) {
		DEBUG(LOG_INFO, "couldn't read on raw listening socket -- ignoring");
		usleep(500000); /* possible down interface, looping condition */
		return -1;
	}
	
	if (bytes < (int) (sizeof(struct iphdr) + sizeof(struct udphdr))) {
		DEBUG(LOG_INFO, "message too short, ignoring");
		return -2;
	}
	
	if (bytes < ntohs(packet.ip.tot_len)) {
		DEBUG(LOG_INFO, "Truncated packet");
		return -2;
	}
	
	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

#if 0	
	/* Make sure its the right packet for us, and that it passes sanity checks */
	if (packet.ip.protocol != IPPROTO_UDP || packet.ip.version != IPVERSION ||
	    packet.ip.ihl != sizeof(packet.ip) >> 2 || packet.udp.dest != htons(CLIENT_PORT) ||
	    bytes > (int) sizeof(struct udp_dhcp_packet) ||
	    ntohs(packet.udp.len) != (short) (bytes - sizeof(packet.ip))) {
	    	DEBUG(LOG_INFO, "unrelated/bogus packet");
	    	return -2;
	}
#endif

	/* check IP checksum */
	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != checksum(&(packet.ip), sizeof(packet.ip))) {
		DEBUG(LOG_INFO, "bad IP header checksum, ignoring");
		return -1;
	}
	
	/* verify the UDP checksum by replacing the header with a psuedo header */
	source = packet.ip.saddr;
	dest = packet.ip.daddr;
	check = packet.udp.check;
	packet.udp.check = 0;
	memset(&packet.ip, 0, sizeof(packet.ip));

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = source;
	packet.ip.daddr = dest;
	packet.ip.tot_len = packet.udp.len; /* cheat on the psuedo-header */
	if (check && check != checksum(&packet, bytes)) {
		DEBUG(LOG_ERR, "packet with bad UDP checksum received, ignoring");
		return -2;
	}
	
	memcpy(payload, &(packet.data), bytes - (sizeof(packet.ip) + sizeof(packet.udp)));
	
	if (ntohl(payload->cookie) != DHCP_MAGIC) {
		LOG(LOG_ERR, "received bogus message (bad magic) -- ignoring");
		return -2;
	}
	DEBUG(LOG_INFO, "oooooh!!! got some!");
	return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
	
}

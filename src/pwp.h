#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<errno.h>

#include<netdb.h>
#include<sys/types.h>
#include<sys/socket.h>

#define MAX_DATA_LEN 128

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
int do_handshake(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);

int pwp_do_handshake(char *md_file)
{
	// TODO:
	// read contents of metadata file
	// parse it using bencode.h and extract info_hash, our_peer_id, peer ip and port.
	// call do_handshake
	return 0;	
}

int do_handshake(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port)
{
	int rv;
	int hs_len;
	uint8_t *hs;
	int socketfd;
	struct sockaddr_in peer;
	uint16_t peer_port;
	int len;
	uint8_t buf[MAX_DATA_LEN];

	rv = 0;
	hs = compose_handshake(info_hash, our_peer_id, &hs_len);
	
	peer_port = htons(port);
	if((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		rv = -1;
		goto cleanup;
	}
	len = sizeof(struct sockaddr_in);
	bzero(&peer, len);
	peer.sin_family = AF_INET;
	peer.sin_port = peer_port;
	if(inet_aton(ip, &peer.sin_addr) == 0)
	{
		fprintf(stderr, "Failed to read in ip address of the peer.\n");
		rv = -1;
		goto cleanup;
	}

	if(send(socketfd, hs, hs_len, 0) == -1)
	{
		perror("send");
		rv = -1;
		goto cleanup;
	}	

	len = recv(socketfd, buf, MAX_DATA_LEN, 0);
	if(len == -1)
	{
		perror("recv");
		rv = -1;
		goto cleanup;
	}

cleanup:
	if(socketfd > 0)
	{
		close(socketfd);
	}
	free(hs);
	return rv;
}

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len)
{
	uint8_t *hs, *curr;
	uint8_t temp;

	*len = 49+19;
	hs = malloc(*len);
	curr = hs;
	temp = 19;
	memcpy(curr, &temp, 1);
	curr += 1;
	strncpy((char *)curr, "BitTorrent protocol", 19);
	curr += 19;
	temp = 0;
	memcpy(curr, &temp, 1);
	curr += 1;
	memcpy(curr, info_hash, 20);
	curr += 20;
	memcpy(curr, our_peer_id, 20);

	return hs;
}

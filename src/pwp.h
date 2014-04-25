#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<errno.h>

#include<netdb.h>
#include<sys/types.h>
#include<sys/socket.h>

struct pwp_handshake
{
	uint8_t prot_name_len;
	uint8_t *prot_name;
	uint8_t reserved[8];
	uint8_t info_hash[20];
	uint8_t peer_id[20];
};

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id);

int pwp_do_handshake(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port)
{
	int rv;
	struct pwp_handshake phs;
	int sockfd;

	// initialise phs
	phs.prot_name_len = 19;
	phs.prot_name = "BitTorrent protocol";	

	rv=0;

cleanup:
	return rv;
}

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id)
{
	uint8_t *hs, *curr;
	uint8_t temp;

	hs = malloc(49+19, 1);
	curr = hs;
	temp = 19;
	memcpy(curr, temp, 1);
	curr += 1;
	strncpy((char *)curr, "BitTorrent protocol", 19);
	curr += 19
	temp = 0;
	memcpy(curr, temp, 1);
	curr += 1;
	memcpy(curr, info_hash, 20);
	curr += 20;
	memcpy(curr, our_peer_id, 20);

	return hs;
}

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<errno.h>

#include<netdb.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "bencode.h"
#include "util.h"

#define MAX_DATA_LEN 128


uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
int do_handshake(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);

int pwp_do_handshake(char *md_file)
{
	uint8_t *metadata;
	const char *str;
	int len;
	long int num;
	int rv = 0;
	bencode_t b1, b2, b3, b4; // bn where n is the level of nestedness
	uint8_t info_hash[20];
	uint8_t our_peer_id[20];
	char *ip;
	uint16_t port;

	if(util_read_whole_file(md_file, &metadata, &len) != 0)
	{
		rv = -1;
		goto cleanup;
	}
	
	// parse it using bencode.h and extract info_hash, our_peer_id, peer ip and port.
	bencode_init(&b1, (const char *)metadata, len);
	
	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "info_hash", 9) != 0)
        {
                rv = -1;
		fprintf(stderr, "Failed to find 'info_hash' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        memcpy(info_hash, str, len);

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "our_peer_id", 11) != 0)
        {
                rv = -1;
		fprintf(stderr, "Failed to find 'our_peer_id' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        memcpy(our_peer_id, str, len);

	// TODO: reading only the first peer. this needs to go in a loop 
	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "peers", 5) != 0)
        {
                rv = -1;
		fprintf(stderr, "Failed to find 'peers' in metadata file.\n");
                goto cleanup;
        }

/********** begining of what will be a while loop for every peer ******************/
	// this is first peer in b3 now. b3 is a dictionary.
	bencode_list_get_next(&b2, &b3);
	
	bencode_dict_get_next(&b3, &b4, &str, &len);
        if(strncmp(str, "ip", 2) != 0)
        {
                rv = -1;
                fprintf(stderr, "Failed to find 'ip' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b4, &str, &len);
	ip = malloc(len + 1); // +1 is to leave space for null terminator char
	memcpy(ip, str, len);
	ip[len] = '\0';

	bencode_dict_get_next(&b3, &b4, &str, &len);
        if(strncmp(str, "port", 4) != 0)
        {
                rv = -1;
                fprintf(stderr, "Failed to find 'port' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b4, &num);
	port = (uint16_t)num;
/********** end of what will be while loop for every peer ****************/

	// call do_handshake
	rv = do_handshake(info_hash, our_peer_id, ip, port);

cleanup:
	if(metadata)
	{
		free(metadata);
	}
	if(ip)
	{
		free(ip);
	}
	return rv;	
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

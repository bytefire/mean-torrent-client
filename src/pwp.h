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
#include<sys/time.h>

#include "bencode.h"
#include "util.h"

#define MAX_DATA_LEN 1024

#define CHOKE_MSG_ID 0
#define UNCHOKE_MSG_ID 1
#define INTERESTED_MSG_ID 2
#define NOT_INTERESTED_MSG_ID 3
#define HAVE_MSG_ID 4
#define BITFIELD_MSG_ID 5
#define REQUEST_MSG_ID 6
#define PIECE_MSG_ID 7
#define CANCEL_MSG_ID 8

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
uint8_t *compose_interested(int *len);

uint8_t extract_msg_id(uint8_t *response);
int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);
int receive_msg(int socketfd, fd_set *recvfd, struct timeval *tv, uint8_t *buf, int *len);

int pwp_start(char *md_file)
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
	while(bencode_list_has_next(&b2))
	{	
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
		// call do_handshake
		printf("*** Going to process peer: %s:%d\n", ip, port);
		rv = talk_to_peer(info_hash, our_peer_id, ip, port);
		if(rv == 1)
		{
			break;
		}
	}
/********** end of what will be while loop for every peer ****************/

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

int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port)
{
	int rv;
	int hs_len;
	uint8_t *hs;
	int socketfd;
	struct sockaddr_in peer;
	uint16_t peer_port;
	int len;
	uint8_t buf[MAX_DATA_LEN];
	fd_set recvfd;
	struct timeval tv;
	uint8_t *msg;
	int msg_len;	

	rv = 0;
	FD_ZERO(&recvfd);
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	hs = compose_handshake(info_hash, our_peer_id, &hs_len);
	
	peer_port = htons(port);
	if((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		rv = -1;
		goto cleanup;
	}
	FD_SET(socketfd, &recvfd);

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

	if(connect(socketfd, (struct sockaddr *)&peer, len) == -1)
        {
                perror("connect");
                return -1;
        }

	/*********** SEND HANDSHAKE ****************/
	if(send(socketfd, hs, hs_len, 0) == -1)
	{
		perror("send");
		rv = -1;
		goto cleanup;
	}	

	/*********** RECEIVE HANDSHAKE ***********/

	rv = receive_msg(socketfd, &recvfd, &tv, buf, &len);
	if(rv == -1)
	{
		goto cleanup;
	}

	/************** SEND INTERESTED ***********************/
	msg = compose_interested(&msg_len);
	
	if(send(socketfd, msg, msg_len, 0) == -1)
        {
                perror("send");
                rv = -1;
                goto cleanup;
        }

	printf("Sent interested message.\n");
	/******** RECEIVE RESPONSE TO INTERESTED *************/
	int recvd_msg_id = -1;
	int unchoked = 0;
	while(recvd_msg_id != UNCHOKE_MSG_ID)
	{
		rv = receive_msg(socketfd, &recvfd, &tv, buf, &len);
        	if(rv == -1)
        	{
                	goto cleanup;
        	}	

		recvd_msg_id = extract_msg_id(buf);
		printf("> Recvd message of length %d. Msg ID = %d.\n", len, recvd_msg_id);
		if(recvd_msg_id == UNCHOKE_MSG_ID)
		{
			unchoked = 1;
		}
	}

	if(unchoked)
	{
		printf("Unchoked by peer!\n");
		rv = 1;
	}
cleanup:
	if(socketfd > 0)
	{
		close(socketfd);
	}
	free(hs);
	return rv;
}


int receive_msg(int socketfd, fd_set *recvfd, struct timeval *tv, uint8_t *buf, int *len)
{
	int rv = 0;
	
	rv = select(socketfd + 1, recvfd, NULL, NULL, tv);
        if(rv == -1)
        {
                perror("select");
                goto cleanup;
        }
        if(rv == 0)
        {
                fprintf(stderr, "Recv timed out.\n");
                rv = -1;
                goto cleanup;
        }

        *len = recv(socketfd, buf, MAX_DATA_LEN, 0);
        if(*len == -1)
        {
                perror("recv");
                rv = -1;
                goto cleanup;
        }

        if(*len == 0)
        {
                fprintf(stderr, "Remote peer closed connection on handshake.\n");
                rv = -1;
                goto cleanup;
        }

        printf("Received handshake reply of length %d\n", *len);
cleanup:
	return rv;
}

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len)
{
	uint8_t *hs, *curr;
	uint8_t temp;
	int i;

	*len = 49+19;
	hs = malloc(*len);
	curr = hs;
	temp = 19;
	memcpy(curr, &temp, 1);
	curr += 1;
	strncpy((char *)curr, "BitTorrent protocol", 19);
	curr += 19;
	temp = 0;
	for(i=0; i<8; i++)
	{
		memcpy(curr, &temp, 1);
		curr += 1;
	}
	memcpy(curr, info_hash, 20);
	curr += 20;
	memcpy(curr, our_peer_id, 20);

	return hs;
}

uint8_t *compose_interested(int *len)
{
	int l;
	uint8_t *msg, *curr;
	uint8_t msg_id = 2; // message if for interested is 2

	*len = 5;
	msg = malloc(*len);
	curr = msg;
	l = htonl(1);
	memcpy(curr, &l, 4);
	
	curr += 4;
	memcpy(curr, &msg_id, 1);

	return msg;
}

uint8_t extract_msg_id(uint8_t *response)
{
	uint8_t msg_id = response[4];
	return msg_id;
}

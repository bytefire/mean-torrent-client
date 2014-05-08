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
#define KEEP_ALIVE_MSG_ID 100

struct pwp_peer
{
        uint8_t peer_id[20]; // TODO: should this be uint8_t peer_id[20]?
        int unchoked;
};

struct pwp_piece
{
	uint8_t peer_id[20]; // TODO: should this be uint8_t peer_id[20]?
	int idx;
};

struct pwp_piece *pieces = NULL;

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
uint8_t *compose_interested(int *len);

uint8_t extract_msg_id(uint8_t *response);
int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);
int receive_msg(int socketfd, int has_hs, fd_set *recvfd, struct timeval *tv, uint8_t **msg, int *len);
/*
Checks if the message in buf is a complete bittorrent peer message.
buf: the message as received from socket
len: length of the message in buf
is_cont: is the message in buf a continuation of BT message which started in an earlier socket message.
has_hs: true if the message in buf contains handshake. if yes then handshake must be at the beginnning.
rl: remaining length. when msg is a continuation then rl is used for input too.
*/
int is_complete(uint8_t *buf, int len, int is_cont, int has_hs, int *rl);
int process_msgs(uint8_t *msgs, int len, int has_hs, struct pwp_peer *peer);

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
	fd_set recvfd;
	struct timeval tv;
	uint8_t *msg;
	int msg_len;	
	uint8_t *recvd_msg;
	struct pwp_peer peer_status;
	
	peer_status.unchoked = 0;
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

	rv = receive_msg(socketfd, 1, &recvfd, &tv, &recvd_msg, &len);
	if(rv == -1)
	{
		goto cleanup;
	}
	process_msgs(recvd_msg, len, 1, &peer_status);
	free(recvd_msg);

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
	while(!peer_status.unchoked)
	{
		// TODO: refactor this set of lines into it's own method. it's repeated whenever we want to receive messages.
		rv = receive_msg(socketfd, 0, &recvfd, &tv, &recvd_msg, &len);
        	if(rv == -1)
        	{
                	goto cleanup;
        	}	
		process_msgs(recvd_msg, len, 0, &peer_status);
		free(recvd_msg);
	}
	
	if(peer_status.unchoked)
        {
		printf("> UNCHOKED!\n");
        }
	
	while(!pieces)
	{
		rv = receive_msg(socketfd, 0, &recvfd, &tv, &recvd_msg, &len);
                if(rv == -1)
                {
                        goto cleanup;
                }
                process_msgs(recvd_msg, len, 0, &peer_status);
                free(recvd_msg);
	}

	// if here then pieces must be populated.
	// TODO: start requesting pieces	


cleanup:
	if(socketfd > 0)
	{
		close(socketfd);
	}
	free(hs);
	return rv;
}


int receive_msg(int socketfd, int has_hs, fd_set *recvfd, struct timeval *tv, uint8_t **msg, int *len)
{
	int rv = 0;
	uint8_t buf[MAX_DATA_LEN];
	int complete = 1; // this must be set to 1 at the start. because when it is false it means the message is continuation of an older one.
	uint8_t *curr;
	int rl, is_cont = 0; // remaining length and is continued

	*msg = malloc(MAX_DATA_LEN);
	curr = *msg;
	do
	{	
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
	
		memcpy(curr, buf, *len);
		complete = is_complete(curr, *len, !complete, has_hs, &rl);
		curr += *len;
	
	} while(!complete);

        printf("Received handshake reply of length %d\n", *len);
cleanup:
	return rv;
}

// TODO: this doesn't take into account the scenario when first four bytes (length of a bt msg) are 
//	broken across two messages
int is_complete(uint8_t *buf, int len, int is_cont, int has_hs, int *rl)
{
	int bt_msg_len;
	int m_rl; // rl = remaining length

	m_rl = 0;
	if(has_hs) // if the message contains handshake then hs must be at start.
	{
		m_rl += (uint8_t)(*buf); // length of protocol name, at the moment 19.
		m_rl += 1 + 8 + 20 + 20; // + length byte + 8 reserved + info hash + our peer id
		
		// 3 possibilities of relative values of hs_jump and len (>,=,<)
		if(m_rl > len)
		{
			*rl = m_rl - len;
			return 0;
		}
		if(m_rl == len)
		{
			*rl = 0;
			return 1;
		}
		// if here then hs_jump < len
		buf += m_rl;
		len = len - m_rl;
	}

	m_rl = *rl;
	if(is_cont) // i.e. continuation of an existing message
	{
	// 3 possibilities: len < rl (incomplete msg), len == rl (complete msg and nothing more), len > rl (complete msg and some more)
		if(len < m_rl)
		{
			*rl = m_rl - len;
			return 0;
		}

		if(len == m_rl)
		{
			*rl = 0;
			return 1;
		}
		// here means len > m_rl
		buf += m_rl;
		len = len - m_rl;
	}

	while(1)
	{
		if(len < 4)
		{
			fprintf(stderr, "!!!!!Problem, because BT message length itself is broken up!!!!!!\n");
			return -1;
		}
		bt_msg_len = ntohl( (*(int *)buf));
		
		if(bt_msg_len + 4 == len)
		{
			*rl = 0;
			return 1;
		}
		if(bt_msg_len + 4 > len)
		{
			*rl = bt_msg_len + 4 - len;
			return 0;
		}
		// if here then there is another msg in buf
		buf += bt_msg_len + 4;
		len = len - bt_msg_len - 4;
	}
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
	if((*(int *)response) == 0) //if length is zero then keep alive msg
	{
		return KEEP_ALIVE_MSG_ID;
	}
	uint8_t msg_id = response[4];
	return msg_id;
}

int process_msgs(uint8_t *msgs, int len, int has_hs, struct pwp_peer *peer)
{
	int rv, jump;
	uint8_t *curr, *temp;
	curr = msgs;
	rv = 0;

	if(has_hs)
	{
		/* 
		1. Extract peer_id
		2. Jump curr to start of next msg and update len accordingly.
		*/
		temp = curr;
		jump = (uint8_t)(*temp) + 1 + 8 + 20;
		temp += jump;
		memcpy(peer->peer_id, temp, 20);
		curr += jump + 20;
		len = len - jump - 20;
	}

	while(len > 0)
	{
		temp = curr;
		switch(extract_msg_id(temp))
		{
			case BITFIELD_MSG_ID:
				// TODO: populate global stats collection
				printf("*-*-* Got BITFIELD message.\n");
				break;
			case UNCHOKE_MSG_ID:
				peer->unchoked = 1;
				printf("*-*-* Got UNCHOKE message.\n");
				break;
			// TODO: other cases
			case CHOKE_MSG_ID:
				peer->unchoked = 0;
				printf("*-*-* Got CHOKE message.\n");
				break;
			case INTERESTED_MSG_ID:
				// TODO:
				printf("*-*-* Got INTERESTED message.\n");
				break;
			case NOT_INTERESTED_MSG_ID:
				// TODO:
				printf("*-*-* Got NOT INTERESTED message.\n");
				break;
			case HAVE_MSG_ID:
				// TODO:
				printf("*-*-* Got HAVE message.\n");
				break;
			case REQUEST_MSG_ID:
				// TODO:
				break;
			case PIECE_MSG_ID:
				// TODO:
				printf("*-*-* Got REQUEST message.\n");
				break;
			case CANCEL_MSG_ID:
				// TODO:
				printf("*-*-* Got CANCEL message.\n");
				break;
			case KEEP_ALIVE_MSG_ID:
			        // TODO:
				printf("*-*-* Got KEEP ALIVE message.\n");
				break;
			default:
				rv = -1;
				goto cleanup;
		}

		// TODO: Move curr to next message and update len accordingly.
		jump = ntohl(*((int *)curr)) + 4;
		curr += jump;
		len = len - jump;
	}

cleanup:
	return rv;
}

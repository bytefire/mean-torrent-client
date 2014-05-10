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

#define RECV_NO_MORE_MSGS 1

#define PIECE_STATUS_NOT_STARTED 0
#define PIECE_STATUS_STARTED 1
#define PIECE_STATUS_COMPLETE 2

#define CONT_NEW 0
#define CONT_HS 1 // handshake
#define CONT_MSG 2 // message continuation
#define CONT_LEN 3 // the 4 bytes containing length of a peer wire protocol message
#define CONT_COMPLETE 4 // the message was complete

struct pwp_peer
{
        uint8_t peer_id[20]; // TODO: should this be uint8_t peer_id[20]?
        int unchoked;
	int has_pieces;
};

struct pwp_piece
{
	struct pwp_peer *peer;
	uint8_t status;
};

struct pwp_piece *pieces = NULL;
long int piece_length = -1;

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
uint8_t *compose_interested(int *len);

uint8_t extract_msg_id(uint8_t *response);
int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);
int receive_msg(int socketfd, int has_hs, fd_set *recvfd, uint8_t **msg, int *len);
/*
Checks if the message in buf is a complete bittorrent peer message.
buf: the message as received from socket
len: length of the message in buf
cont_status: continuation status of the message. this is one of the CONT_* constants defined above.
rl: remaining length. when msg is a continuation then rl is used for input too.

returns: one of the CONT_* constants indicating status
*/
int is_complete(uint8_t *buf, int len, int cont_status, int *rl);
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

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "num_of_pieces", 13) != 0)
        {
                rv = -1;
                fprintf(stderr, "Failed to find 'num_of_pieces' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b2, &num);
	pieces = malloc(sizeof(struct pwp_piece) * num);
	bzero(pieces, sizeof(struct pwp_piece) * num);

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "piece_length", 12) != 0)
        {
                rv = -1;
                fprintf(stderr, "Failed to find 'piece_length' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b2, &piece_length);
        
	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "peers", 5) != 0)
        {
                rv = -1;
		fprintf(stderr, "Failed to find 'peers' in metadata file.\n");
                goto cleanup;
        }

/********** begining of what will be a while loop for every peer ******************/
	while(bencode_list_has_next(&b2))
	{	
		bencode_list_get_next(&b2, &b3);
	
		// this is a peer in b3 now. b3 is a dictionary.
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
	uint8_t *msg;
	int msg_len;	
	uint8_t *recvd_msg;
	struct pwp_peer peer_status;
	
	peer_status.unchoked = 0;
	peer_status.has_pieces = 0;
	rv = 0;
	FD_ZERO(&recvfd);

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

	/*********** RECEIVE HANDSHAKE + BITFIELD + HAVE's (possibly) ***********/
	int temp_hs = 1;
	do
	{
		rv = receive_msg(socketfd, temp_hs, &recvfd, &recvd_msg, &len);
		if(rv == -1)
		{
			goto cleanup;
		}
		if(rv != RECV_NO_MORE_MSGS)
		{
			process_msgs(recvd_msg, len, temp_hs, &peer_status);
		}
		if(recvd_msg)
		{
			free(recvd_msg);
			recvd_msg = NULL;
		}
		temp_hs = 0;
	} while(rv != RECV_NO_MORE_MSGS);
	// check if this peer has any pieces we don't have and then send interested.
	if(!peer_status.has_pieces)
	{
		printf("** Peer has no pieces, so not sending interested.\n");
		rv = -1;
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
	while(!peer_status.unchoked)
	{
		// TODO: refactor this set of lines into it's own method. it's repeated whenever we want to receive messages.
		rv = receive_msg(socketfd, 0, &recvfd, &recvd_msg, &len);
        	if(rv == -1)
        	{
                	goto cleanup;
        	}	
		process_msgs(recvd_msg, len, 0, &peer_status);
		free(recvd_msg);
		recvd_msg = NULL;
	}
	rv = 0;
	
	// if here then pieces must be populated and we're unchoked too.
	// TODO: start requesting pieces	


cleanup:
	if(socketfd > 0)
	{
		close(socketfd);
	}
	free(hs);
	return rv;
}


int receive_msg(int socketfd, int has_hs, fd_set *recvfd, uint8_t **msg, int *len)
{
	int rv = 0;
	uint8_t buf[MAX_DATA_LEN];
	int complete = 0, cont_status = CONT_NEW;
	uint8_t *curr;
	int rl, is_cont = 0; // remaining length and is continued
	struct timeval tv;

	tv.tv_sec = 5;
        tv.tv_usec = 0;
	*msg = malloc(MAX_DATA_LEN);
	curr = *msg;
	if(has_hs)
	{
		cont_status = CONT_HS;
	}
	do
	{	
		rv = select(socketfd + 1, recvfd, NULL, NULL, &tv);
        	printf("** receive_msgs: value of 'rv' after select: %d\n", rv);

		if(rv == -1)
        	{
			printf("receive_msg: Error while select()ing.\n");
                	perror("select");
                	goto cleanup;
        	}
	        if(rv == 0) // i.e. timeout
        	{
			if((cont_status == CONT_MSG) || (cont_status == CONT_LEN))
			{
				fprintf(stderr, "** receive_msg: recv TIMED OUT with INCOMPLETE msg.\n");
				rv = -1;
			}
			else
			{
	                	printf("receive_msg: Recv timed out.\n");
				rv = RECV_NO_MORE_MSGS;
			}
        	        goto cleanup;
	        }
		// reset rv
		rv = 0;
        	*len = recv(socketfd, buf, MAX_DATA_LEN, 0);
        	if(*len == -1)
	        {
			printf("receive_msg: Error while recv()ing.\n");
        	        perror("recv");
	                rv = -1;
                	goto cleanup;
        	}

	        if(*len == 0)
        	{
               		printf("Remote peer closed connection on handshake.\n");
                	rv = -1;
        	        goto cleanup;
	        }
		
		printf("** receive_msg: Received msg of length: %d\n", *len);	
		memcpy(curr, buf, *len);
		cont_status = is_complete(curr, *len, cont_status, &rl);
		curr += *len;
	} while(cont_status != CONT_COMPLETE);

        printf("receive_msg: Received complete msg(s) of length %d\n", *len);
cleanup:
	return rv;
}


int is_complete(uint8_t *buf, int len, int cont_status, int *rl)
{
	int bt_msg_len;
	int m_rl; // rl = remaining length

	m_rl = 0;

	// handle situation if length of BT message was broken up
	if(cont_status == CONT_LEN)
	{
		// if here then 4 bytes must be like this: 
		// 	bytes 0 to 2: bytes from previous msg in the same order as the msg (i.e. network order)
		// 	byte 3: number of bytes remaining to complete the 4 bytes of msg len
		
		uint8_t *curr = (uint8_t *)rl;
		m_rl = (int)(*(curr + 3));
		if(len < m_rl)
		{
			// copy whatever bytes are available and update last byte of rl.
			memcpy(curr + 4 - m_rl, buf, len);
			m_rl = m_rl - len;
			uint8_t temp_len = (uint8_t)m_rl;
			memcpy(curr + 3, &temp_len, 1);
			return CONT_LEN;
		}
		else
		{
			// else copy the length into rl and do the ntohl conversion.
			// reset things for normal continuation further below.
			memcpy(curr + 4 - m_rl, buf, m_rl);
			len = len - m_rl;
			buf += m_rl;
			m_rl = ntohl(*rl);
			*rl = m_rl;
			cont_status = CONT_MSG;
		}
	}
	
	if(cont_status == CONT_HS) // if the message contains handshake then hs must be at start.
	{
		m_rl += (uint8_t)(*buf); // length of protocol name, at the moment 19.
		m_rl += 1 + 8 + 20 + 20; // + length byte + 8 reserved + info hash + our peer id
		
		// 3 possibilities of relative values of hs_jump and len (>,=,<)
		if(m_rl > len)
		{
			*rl = m_rl - len;
			return CONT_MSG;
		}
		if(m_rl == len)
		{
			*rl = 0;
			return CONT_COMPLETE;
		}
		// if here then hs_jump < len
		buf += m_rl;
		len = len - m_rl;
	}

	m_rl = *rl;
	if(cont_status == CONT_MSG) // i.e. continuation of an existing message
	{
	// 3 possibilities: len < rl (incomplete msg), len == rl (complete msg and nothing more), len > rl (complete msg and some more)
		if(len < m_rl)
		{
			*rl = m_rl - len;
			return CONT_MSG;
		}

		if(len == m_rl)
		{
			*rl = 0;
			return CONT_COMPLETE;
		}
		// here means len > m_rl
		buf += m_rl;
		len = len - m_rl;
	}

	while(1)
	{
		if(len < 4)
		{
			// copy whatever bytes are available and update last byte of rl.
			uint8_t *curr = (uint8_t *)rl;
                        memcpy(curr, buf, len);
                        uint8_t temp_len = (uint8_t)(4 - len);
                        memcpy(curr + 3, &temp_len, 1);
                        return CONT_LEN;
		}
		bt_msg_len = ntohl( (*(int *)buf));
		
		if(bt_msg_len + 4 == len)
		{
			*rl = 0;
			return CONT_COMPLETE;
		}
		if(bt_msg_len + 4 > len)
		{
			*rl = bt_msg_len + 4 - len;
			return CONT_MSG;
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
	if(!msgs)
	{
		fprintf(stderr, "ERROR: process_msgs: MSGS is null.\n");
		return -1;
	}

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
				peer->has_pieces = 1;
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
				peer->has_pieces = 1;
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

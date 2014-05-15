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

#define RECV_OK 0
#define RECV_TO 1 // normal timeout
#define RECV_ERROR -1 // error e.g. when received only 2 bytes from the 4 bytes which specify length of msg

#define PIECE_STATUS_NOT_AVAILABLE 0
#define PIECE_STATUS_AVAILABLE 1
#define PIECE_STATUS_STARTED 2
#define PIECE_STATUS_COMPLETE 3 

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
long int num_of_pieces = -1;

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
uint8_t *compose_interested(int *len);

uint8_t extract_msg_id(uint8_t *response);
int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port);

int receive_msg(int socketfd, fd_set *recvfd, uint8_t **msg, int *len);
int receive_msg_hs(int socketfd, fd_set *recvfd, uint8_t **msg, int *len);
int get_len(int socketfd, fd_set *recvfd, int *len);
int get_len_hs(int socketfd, fd_set *recvfd, int *len);
int process_msgs(uint8_t *msgs, int len, int has_hs, struct pwp_peer *peer);
int receive_msg_for_len(int socketfd, fd_set *recvfd, int len, uint8_t **msg);
int process_have(uint8_t *msg, struct pwp_peer *peer);
int process_bitfield(uint8_t *msg, struct pwp_peer *peer); 
int choose_random_piece_idx();
int download_piece(int idx);

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
        bencode_int_value(&b2, &num_of_pieces);
	pieces = malloc(sizeof(struct pwp_piece) * num_of_pieces);
	bzero(pieces, sizeof(struct pwp_piece) * num_of_pieces);

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
		
		printf("[LOG] pwp_start: rv from talk_to_peer is %d.\n\n", rv);
		if(rv == 0)
		{
			break;
		}
	}
/********** end of what will be while loop for every peer ****************/

cleanup:
	printf("[LOG] In pwp_start's cleanup.\n");
	if(metadata)
	{
		printf("[LOG] Freeing metadata.\n");
		free(metadata);
	}
	if(ip)
	{
		printf("[LOG] Freeing IP.\n");
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
	uint8_t *recvd_msg = NULL;
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
	printf("[LOG] Sent handshake.\n");
	if(send(socketfd, hs, hs_len, 0) == -1)
	{
		perror("send");
		rv = -1;
		goto cleanup;
	}	

	/*********** RECEIVE HANDSHAKE + BITFIELD + HAVE's (possibly) ***********/
	rv = receive_msg_hs(socketfd, &recvfd, &recvd_msg, &len);
	printf("[LOG] rv from receive_msg: %d.\n", rv);
        if(rv == RECV_ERROR)
        {
		goto cleanup;
        }
        if(rv != RECV_TO)
        {
		printf("[LOG] Received handshake response of length %d. Going to process it now.\n", len);
		process_msgs(recvd_msg, len, 1, &peer_status);
		printf("[LOG] Done pocessing handshake.\n");
        }
        if(recvd_msg)
        {
		free(recvd_msg);
                recvd_msg = NULL;
        }	

	do
	{
		rv = receive_msg(socketfd, &recvfd, &recvd_msg, &len);
		printf("[LOG] rv from receive_msg: %d.\n", rv);
		if(rv == RECV_ERROR)
		{
			goto cleanup;
		}
		if(rv != RECV_TO)
		{
			printf("[LOG] Received next msg after HS. Len: %d. Goinf to process it now.\n", len);
			process_msgs(recvd_msg, len, 0, &peer_status);
		}
		if(recvd_msg)
		{
			free(recvd_msg);
			recvd_msg = NULL;
		}
	} while(rv != RECV_TO);

	printf("[LOG] Finished receiving until timeout. Checking if peer has any pieces.\n");
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

	printf("[LOG] Sent interested message. Receiving response now.\n");
	/******** RECEIVE RESPONSE TO INTERESTED *************/
	while(!peer_status.unchoked)
	{
		// TODO: refactor this set of lines into it's own method. it's repeated whenever we want to receive messages.
		rv = receive_msg(socketfd, &recvfd, &recvd_msg, &len);
		printf("[LOG] rv from receive_msg: %d.\n", rv);
        	if(rv == RECV_ERROR)
        	{
                	goto cleanup;
        	}
		if(rv == RECV_TO)
		{
			goto cleanup;
		}

		printf("[LOG] Received response for INTERESTED message. Going to process it now.\n");
		process_msgs(recvd_msg, len, 0, &peer_status);
		if(recvd_msg)
		{
			free(recvd_msg);
			recvd_msg = NULL;
		}
	}
	rv = 0;
	printf("[LOG] Peer has unchoked us.\n");	
	// if here then pieces must be populated and we're unchoked too.
	// TODO: start requesting pieces	


cleanup:
	printf("[LOG] In cleanup.\n");
	if(socketfd > 0)
	{
		printf("[LOG] Closing socket.\n");
		close(socketfd);
	}
	if(hs)
	{
		printf("[LOG] Freeing HS.\n");
		free(hs);
		hs = NULL;
	}
	if(recvd_msg)
        {
		printf("[LOG] Freeing recvd_msg.\n");
		free(recvd_msg);
                recvd_msg = NULL;
        }
	return rv;
}

int receive_msg_hs(int socketfd, fd_set *recvfd, uint8_t **msg, int *len)
{
        int rv;
	uint8_t *curr;

        rv = get_len_hs(socketfd, recvfd, len);
        if(rv != RECV_OK)
        {
                fprintf(stderr, "[LOG] inside receive_msg_hs: get_len_hs didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                goto cleanup;
        }

        *msg = malloc(*len + 1);
	curr = *msg;
	*curr = (uint8_t)(*len - 8 - 20 - 20);
	curr++;
        rv = receive_msg_for_len(socketfd, recvfd, *len, &curr);
        if(rv != RECV_OK)
        {
                fprintf(stderr, "[ERROR] inside receive_msg_hs: receive_msg_for_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                rv = RECV_ERROR; // even if it is timeout, at this stage it means error.
                goto cleanup;
        }

cleanup:
        return rv;
}

int receive_msg(int socketfd, fd_set *recvfd, uint8_t **msg, int *len)
{
	int rv, temp;
	uint8_t *curr;

	rv = get_len(socketfd, recvfd, len);
	if(rv != RECV_OK)
	{
		fprintf(stderr, "[LOG] inside receive_msg: get_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
		goto cleanup;
	}

	*msg = malloc(*len + 4);
	curr = *msg;
	temp = htonl(*len);
	memcpy(curr, &temp, 4);
	curr += 4;
	rv = receive_msg_for_len(socketfd, recvfd, *len, &curr);
	if(rv != RECV_OK)
	{
		fprintf(stderr, "[ERROR] inside receive_msg: receive_msg_for_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                rv = RECV_ERROR; // even if it is timeout, at this stage it means error.
		goto cleanup;
	}

cleanup:
	return rv;
}

int get_len(int socketfd, fd_set *recvfd, int *len)
{
	int rv;
	uint8_t *curr = (uint8_t *)len;

	rv = receive_msg_for_len(socketfd, recvfd, 4, &curr);	
	*len = ntohl(*len);	

	return rv;
}

int get_len_hs(int socketfd, fd_set *recvfd, int *len)
{
        int rv;
	uint8_t *p_name_len = malloc(1);

        rv = receive_msg_for_len(socketfd, recvfd, 1, &p_name_len);

        *len = *p_name_len + 8 + 20 + 20;

        return rv;
}

int receive_msg_for_len(int socketfd, fd_set *recvfd, int len, uint8_t **msg)
{
	int r_bytes, rv;
        uint8_t *curr = *msg;
	struct timeval tv;

	tv.tv_sec = 5;
        tv.tv_usec = 0;
        // TODO: the for-loop to keep receiving until we have received the 4 bytes which specify length.
        rv = select(socketfd + 1, recvfd, NULL, NULL, &tv);
        printf("[LOG] get_len: value of 'rv' after select: %d (1=OK; 0=timeout; -1=error)\n", rv);

        if(rv == -1)
        {
                perror("select");
                return RECV_ERROR;
        }
        if(rv == 0) // i.e. timeout
        {
                return RECV_TO;
        }
        rv = 0;
        for(r_bytes = 0; r_bytes<len; r_bytes+=rv)
        {
                if((rv = recv(socketfd, curr + r_bytes, len - r_bytes, 0)) <= 0)
                {
                        return RECV_ERROR;
                }
        }

        return RECV_OK;
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
		printf("*-*-* Got HANDSHAKE message.\n");
	}

	while(len > 0)
	{
		temp = curr;
		switch(extract_msg_id(temp))
		{
			case BITFIELD_MSG_ID:
				// TODO: populate global stats collection
				printf("*-*-* Got BITFIELD message.\n");
				process_bitfield(temp, peer);
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
				process_have(temp, peer);
				peer->has_pieces = 1;
				break;
			case REQUEST_MSG_ID:
				// TODO:
				printf("*-*-* Got REQUEST message.\n");
				break;
			case PIECE_MSG_ID:
				// TODO:
				printf("*-*-* Got PIECE message.\n");
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

int download_piece(int idx)
{
    /* TODO:
    1. Calculate number of blocks in this piece (2^14 (16384) bytes per block )
    2. malloc an array 'blocks' of struct pwp_block for this piece 
    3. initialise each pwp_block in the blocks array
    LOOP:
        4. create three REQUEST messages for three blocks which don't have status DOWNLOADED. if no such block then break the loop
        5. receive PIECE msgs and save data (write different method for piece messages, not receive_msg)
        6. keep receiving until timeout.
        7. update 'blocks' array
        8. go to step 4
    END OF LOOP
    9. compute sha1 of downloaded piece
    10. verify the sha1 with the one in announce file. (or metada file?)
    11. return 0 or -1 accordingly.
    */
	return 0;
} 

int process_bitfield(uint8_t *msg, struct pwp_peer *peer)
{
    uint8_t *curr = msg;
    int i, j, rv, idx;
    uint8_t bits, mask;
      
    rv = 0;
    // read bitfield, parse it and populate pieces array accordingly.
    int len = ntohl((int)(*curr));
    curr += 5; // get to start of bitfield.
      
    for(i=0; i<len; i++)
    {
        bits = *(curr + i);
        mask = 0x80;
        for(j=0; j<8; j++)
        {
            if(bits & mask)
            {
                idx = i*8 + j;
                if(idx >= num_of_pieces)
                {
                    fprintf(stderr, "[ERROR] Bitfield has more bits set than there are number of pieces.\n");
                    rv = -1;
                    // TODO: Reset all pieces that were set to available for this particular peer.
                    goto cleanup;
                }
                if(pieces[idx].status == PIECE_STATUS_NOT_AVAILABLE)
                {
                    pieces[idx].status = PIECE_STATUS_AVAILABLE;
                    pieces[idx].peer = peer;
                }
            }
            mask = mask / 2;
        }
    }

cleanup:
    return rv;
}
  
int process_have(uint8_t *msg, struct pwp_peer *peer)
{
    int rv = 0;
    uint8_t *curr = msg;
    int idx = ntohl((int)(*(curr+5)));
      
    if(pieces[idx].status == PIECE_STATUS_NOT_AVAILABLE)
    {
        pieces[idx].status = PIECE_STATUS_AVAILABLE;
        pieces[idx].peer = peer;
    }

    return rv;
} 

int choose_random_piece_idx()
{
    int i, r, random_piece_idx;
      
    random_piece_idx = -1;
    srand(time(NULL));
      
    for(i=0; i<10; i++) // 10 attempts at getting a random available piece
    {
        r = rand() % num_of_pieces;
        if(pieces[r].status == PIECE_STATUS_AVAILABLE)
        {
            random_piece_idx = r;
            break;
        }
    }
      
    // if no piece found after random attempts then go sequentially
    if(random_piece_idx == -1)
    {
        for(i=0; i<num_of_pieces; i++)
        {
            if(pieces[i].status == PIECE_STATUS_AVAILABLE)
            {
                random_piece_idx = i;
                break;
            }
        }
    }
      
    return random_piece_idx;
}

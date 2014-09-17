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
#include<pthread.h>
#include<fcntl.h>

#include "bencode.h"
#include "util.h"
#include "bf_logger.h"
#include "sha1.h"

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

#define BLOCK_LEN 16384 // i.e. 2^14 which is commonly used
#define BLOCK_STATUS_NOT_DOWNLOADED 0
#define BLOCK_STATUS_DOWNLOADED 1 

#define BLOCK_REQUESTS_COUNT 3 // max no of requests sent every time

#define MAX_THREADS 4
#define PIECES_TO_DOWNLOAD 3

struct pwp_peer
{
        uint8_t peer_id[20]; // TODO: should this be uint8_t peer_id[20]?
        int unchoked;
	int has_pieces;
};

struct pwp_peer_node // node for linked list of peers
{
	struct pwp_peer *peer;
	struct pwp_peer_node *next;
};

struct pwp_piece
{
	struct pwp_peer_node *peers; // this is the HEAD pointer
	uint8_t status; // this is one of the PIECE_STATUS values
};

struct pwp_block
{
    int offset;
    int length;
    uint8_t status;
};

struct talk_to_peer_args
{
    uint8_t *info_hash;
    uint8_t *our_peer_id;
    char *ip;
    uint16_t port;
};

struct thread_data
{
	struct talk_to_peer_args *args;
	pthread_t thread_descriptor;
};

struct pwp_piece *g_pieces = NULL;
long int g_piece_length = -1;
long int g_num_of_pieces = -1;
long int g_downloaded_pieces = 0;
uint8_t *g_piece_hashes;
char *g_saved_filepath = NULL;
char *g_resume_filepath = NULL;

pthread_mutex_t *g_pieces_mutexes = NULL;
// used to lock one byte of resume file when updating it. there will be one mutex per byte of the resume file
pthread_mutex_t *g_resume_mutexes = NULL;
pthread_mutex_t g_downloaded_pieces_mutex = PTHREAD_MUTEX_INITIALIZER;

uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len);
uint8_t *compose_interested(int *len);
uint8_t *compose_request(int piece_idx, int block_offset, int block_length, int *len);

uint8_t extract_msg_id(uint8_t *response);
void *talk_to_peer(void *args);

int receive_msg(int socketfd, fd_set *recvfd, uint8_t **msg, int *len);
int receive_msg_hs(int socketfd, fd_set *recvfd, uint8_t **msg, int *len);
int get_len(int socketfd, fd_set *recvfd, int *len);
int get_len_hs(int socketfd, fd_set *recvfd, int *len);
int process_msgs(uint8_t *msgs, int len, int has_hs, struct pwp_peer *peer);
int receive_msg_for_len(int socketfd, fd_set *recvfd, int len, uint8_t *msg);
int process_have(uint8_t *msg, struct pwp_peer *peer);
int process_bitfield(uint8_t *msg, struct pwp_peer *peer); 
int choose_random_piece_idx(uint8_t *peer_id);
int are_same_peers(uint8_t *peer_id1, uint8_t *peer_id2);
void linked_list_add(struct pwp_peer_node **head, struct pwp_peer *peer);
int linked_list_contains_peer_id(struct pwp_peer_node *head, uint8_t *peer_id);
void linked_list_free(struct pwp_peer_node **head);
int get_pieces(int socketfd, struct pwp_peer *peer);
int download_piece(int idx, int socketfd, FILE *savedfp, struct pwp_peer *peer);
uint8_t *prepare_requests(int piece_idx, struct pwp_block *blocks, int num_of_blocks, int max_requests, int *len);
int download_block(int socketfd, int expected_piece_idx, FILE *savedfp, struct pwp_block *block, struct pwp_peer *peer);
int initialise_pieces(struct pwp_piece *pieces, const char *path_to_resume_file);
int update_resume_file(const char *path_to_resume_file, int downloaded_piece_index);

int pwp_start(const char *md_filepath, const char *saved_filepath, const char *resume_filepath)
{
//	bf_logger_init(LOG_FILE);

	bf_log("++++++++++++++++++++ START:  PWP_START +++++++++++++++++++++++\n");

	uint8_t *metadata;
	const char *str;
	int len, i;
	long int num;
	int rv = 0;
	bencode_t b1, b2, b3, b4; // bn where n is the level of nestedness
	uint8_t info_hash[20];
	uint8_t our_peer_id[20];
	char *ip;
	uint16_t port;

	g_saved_filepath = saved_filepath;
	g_resume_filepath = resume_filepath;

	if(util_read_whole_file(md_filepath, &metadata, &len) != 0)
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
		bf_log( "Failed to find 'info_hash' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        memcpy(info_hash, str, len);

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "our_peer_id", 11) != 0)
        {
                rv = -1;
		bf_log(  "Failed to find 'our_peer_id' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        memcpy(our_peer_id, str, len);

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "num_of_pieces", 13) != 0)
        {
                rv = -1;
                bf_log(  "Failed to find 'num_of_pieces' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b2, &g_num_of_pieces);

	g_pieces = calloc(sizeof(struct pwp_piece) * g_num_of_pieces, 1);
        if(initialise_pieces(g_pieces, g_resume_filepath) == -1)
	{
		rv = -1;
		bf_log("[ERROR] pwp_start(): Failied to initialise g_pieces. Aborting.\n");
		goto cleanup;
	}

        g_pieces_mutexes = malloc(sizeof(pthread_mutex_t) * g_num_of_pieces);
        for(i=0; i<g_num_of_pieces; i++)
        {
                 pthread_mutex_init(&g_pieces_mutexes[i], NULL);
        }

	int num_of_resume_bytes = g_num_of_pieces / 8;
	num_of_resume_bytes += (g_num_of_pieces % 8) ? 1 : 0;
	g_resume_mutexes = malloc(sizeof(pthread_mutex_t) * num_of_resume_bytes);
        for(i=0; i<num_of_resume_bytes; i++)
        {
                 pthread_mutex_init(&g_resume_mutexes[i], NULL);
        }

        bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "piece_length", 12) != 0)
        {
                rv = -1;
                bf_log(  "Failed to find 'piece_length' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b2, &g_piece_length);	

	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "piece_hashes", 12) != 0)
        {
                rv = -1;
                bf_log(  "Failed to find 'piece_hashes' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        g_piece_hashes = malloc(len);
        memcpy(g_piece_hashes, str, len);
	
	bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "peers", 5) != 0)
        {
                rv = -1;
		bf_log(  "Failed to find 'peers' in metadata file.\n");
                goto cleanup;
        }

	struct talk_to_peer_args *args;
	pthread_t thread1;
	int t1_rv, thread_count;
	void *ttp_rv;		
	struct thread_data *td = malloc(MAX_THREADS * sizeof(struct thread_data));

	thread_count = 0;

/******** INITIAL loop to start initial MAX_THREADS threads ************/

// NOTE: throughout this application one thread talks to one peer only.

	while((extract_next_peer(&b2, &ip, &port) == 0) && (thread_count < MAX_THREADS))
	{	
		args = malloc(sizeof(struct talk_to_peer_args));
		args->info_hash = info_hash;
		args->our_peer_id = our_peer_id;
		args->ip = ip;
		args->port = port;
		t1_rv = pthread_create(&thread1, NULL, talk_to_peer, (void *)args);
		
		td[thread_count].args = args;
		td[thread_count].thread_descriptor = thread1;	
		bf_log("[LOG] pwp_start(): Started a fresh thread with id: %d.\n", thread1);
		thread_count++;
	}

	rv = -1;
	
	int count = 0;
	struct timespec ts;

/********** SECOND loop to replace any completed threads with new ones. *******************/
	while(count < PIECES_TO_DOWNLOAD)
	{
		// this for loop goes over each thread checking if it has completed. 
		for(thread_count = 0; thread_count < MAX_THREADS; thread_count++)
		{
			clock_gettime(CLOCK_REALTIME, &ts);
        	        ts.tv_sec += 1;
	                rv = pthread_timedjoin_np(td[thread_count].thread_descriptor, &ttp_rv, &ts);
			if(rv == 0) // rv == 0 means that the thread completed execution
			{
				// 1. free resources
				bf_log("[LOG] pwp_start: >>> Thread Completed <<< rv from talk_to_peer thread id: %d is %d.\n\n", td[thread_count].thread_descriptor, (int)ttp_rv);
				free(td[thread_count].args);
				td[thread_count].args = NULL;

				// 2. start new thread in its place
				if(extract_next_peer(&b2, &ip, &port) == 0)
			        {
		                	args = malloc(sizeof(struct talk_to_peer_args));
        		        	args->info_hash = info_hash;
                			args->our_peer_id = our_peer_id;
	        		        args->ip = ip;
        		        	args->port = port;
	               		 	t1_rv = pthread_create(&thread1, NULL, talk_to_peer, (void *)args);
		
			                td[thread_count].args = args;
                			td[thread_count].thread_descriptor = thread1;
					bf_log("[LOG] pwp_start(): Started a replacement thread with id: %d.\n", thread1);
				}
                	}
			else
			{
				bf_log("[LOG] ********pwp_start(): Couldn't join thread %d within timeout.\n", td[thread_count].thread_descriptor);
			}
        	}
	
		


		/* -X-X-X- CRITICAL REGION START -X-X-X- */
		pthread_mutex_lock(&g_downloaded_pieces_mutex);
	
		count = g_downloaded_pieces;

		pthread_mutex_unlock(&g_downloaded_pieces_mutex);
		/* -X-X-X- CRITICAL REGION END -X-X-X- */
	}
	bf_log("[LOG] pwp_start(): Finished the while loop to download at least 3 pieces. Going to join all threads.\n");
		
	// Final for-loop to ensure that all the threads have joined
	for(thread_count = 0; thread_count < MAX_THREADS; thread_count++)
	{
		bf_log("[LOG] pwp_start(): Joining thread %d.\n", td[thread_count].thread_descriptor);
		pthread_join(td[thread_count].thread_descriptor, NULL);
		 bf_log("[LOG] pwp_start(): Successfully joined thread %d.\n", td[thread_count].thread_descriptor);
		if(td[thread_count].args)
		{
			free(td[thread_count].args);
			td[thread_count].args = NULL;
		}
	}

	free(td);
/********** end of what will be while loop for every peer ****************/
	rv = 0; // if here then things have gone according to plan.

cleanup:
	bf_log(" ------------------------------------ FINISH: PWP_START  ----------------------------------------\n");
	if(metadata)
	{
		bf_log("[LOG] Freeing metadata.\n");
		free(metadata);
	}
	if(ip)
	{
		bf_log("[LOG] Freeing IP.\n");
		free(ip);
	}

	if(g_pieces)
	{
		bf_log("[LOG] pwp_start: before freeing g_pieces, freeing linked lists of peers inside each piece.\n");
		for(i=0; i<g_num_of_pieces; i++)
		{
			linked_list_free(&g_pieces[i].peers);
		}
		bf_log("[LOG] pwp_start: freeing g_pieces.\n");
		free(g_pieces);
	}
	if(g_pieces_mutexes)
	{
		bf_log("[LOG] pwp_start: freeing g_pieces_mutexes.\n");
		free(g_pieces_mutexes);
	}
	if(g_resume_mutexes)
	{
		bf_log("[LOG] pwp_start: freeing g_resume_mutexes.\n");
		free(g_resume_mutexes);
	}
	if(g_piece_hashes)
        {
                bf_log("[LOG] pwp_start: freeing g_piece_hashes.\n");
                free(g_piece_hashes);
        }
	
	return rv;	
}

int extract_next_peer(bencode_t *list_of_peers, char **ip, uint16_t *port)
{
	bf_log("++++++++++++++++++++ START:  EXTRACT_NEXT_PEER +++++++++++++++++++++++\n");
	int rv = 0;
	bencode_t b1, b2;
	const char *str;
        int len;
        long int num;
	
	if(!bencode_list_has_next(list_of_peers))
        {
		bf_log("[LOG] extract_next_peer: no more peers.\n");
		rv = -1;
		goto cleanup;
	}
        
	bencode_list_get_next(list_of_peers, &b1);

        // this is a peer in b1 now and b1 is a dictionary.
        bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "ip", 2) != 0)
        {
		rv = -1;
                bf_log("[LOG] Failed to find 'ip' in metadata file.\n");
                goto cleanup;
        }
        bencode_string_value(&b2, &str, &len);
        *ip = malloc(len + 1); // +1 is to leave space for null terminator char
        memcpy(*ip, str, len);
        (*ip)[len] = '\0';

        bencode_dict_get_next(&b1, &b2, &str, &len);
        if(strncmp(str, "port", 4) != 0)
        {
		rv = -1;
                bf_log(  "Failed to find 'port' in metadata file.\n");
                goto cleanup;
        }
        bencode_int_value(&b2, &num);
        *port = (uint16_t)num;

cleanup:
	bf_log(" ------------------------------------ FINISH: EXTRACT_NEXT_PEER ----------------------------------------\n");
	return rv;

}

// int talk_to_peer(uint8_t *info_hash, uint8_t *our_peer_id, char *ip, uint16_t port)
void *talk_to_peer(void *args)
{
	bf_log("++++++++++++++++++++ START:  TALK_TO_PEER +++++++++++++++++++++++\n");

	int rv, valopt;
	int hs_len;
	uint8_t *hs;
	int socketfd;
	long int socket_flags;
	struct sockaddr_in peer;
	socklen_t lon;
	uint16_t peer_port;
	int len;
	fd_set recvfd;
	struct timeval tv;
	uint8_t *msg;
	int msg_len;	
	uint8_t *recvd_msg = NULL;
	struct pwp_peer peer_status;

	struct talk_to_peer_args *ttp_args = (struct talk_to_peer_args *)args;	

	bf_log("*** Going to process peer: %s:%d\n", ttp_args->ip, ttp_args->port);

	peer_status.unchoked = 0;
	peer_status.has_pieces = 0;
	rv = 0;
	FD_ZERO(&recvfd);
	tv.tv_sec = 10;
	tv.tv_usec = 0;

	hs = compose_handshake(ttp_args->info_hash, ttp_args->our_peer_id, &hs_len);
	
	peer_port = htons(ttp_args->port);
	if((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		rv = -1;
		goto cleanup;
	}

	// set the socket to non-blocking when making connection. we'll set it back to blocking
	// once it is connected. we set it to non-blocking so that we can do timeout on connect().
	socket_flags = fcntl(socketfd, F_GETFL, NULL);
	socket_flags |= O_NONBLOCK;
	fcntl(socketfd, F_SETFL, socket_flags);

	FD_SET(socketfd, &recvfd);

	len = sizeof(struct sockaddr_in);
	bzero(&peer, len);
	peer.sin_family = AF_INET;
	peer.sin_port = peer_port;
	if(inet_aton(ttp_args->ip, &peer.sin_addr) == 0)
	{
		bf_log("[ERROR] talk_to_peer(): Failed to read in ip address of the peer.\n");
		rv = -1;
		goto cleanup;
	}

	bf_log("[LOG] Going to connect with the peer.\n");
	rv = connect(socketfd, (struct sockaddr *)&peer, len);

	if(rv < 0)
	{
		if(errno == EINPROGRESS)
		{
			if(select(socketfd+1, NULL, &recvfd, NULL, &tv) > 0)
			{
				/* >>>>>>>>>>>>>>>>> HERE!!! <<<<<<<<<<<<<<<<<<<*/
				lon = sizeof(int);
				getsockopt(socketfd, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon);
				if(valopt)
				{
					bf_log("[ERROR] Error in connection() %d - %s\n", valopt, strerror(valopt));
					rv = -1;
					goto cleanup;
				}
			}
			else
			{
				bf_log("[LOG] Connection either timed out...\n");
				rv = -1;
				goto cleanup;
			}
		}
		else
		{
			bf_log("[LOG] Got error when connecting to a peer: %d - %s\n", errno, strerror(errno));
			rv = -1;
			goto cleanup;
		}
	}

	// set the socket back to blocking...
	socket_flags = fcntl(socketfd, F_GETFL, NULL);
	socket_flags &= (~O_NONBLOCK);
	fcntl(socketfd,F_SETFL, socket_flags);

	bf_log("[LOG] Connected successfully.\n");

	/*********** SEND HANDSHAKE ****************/
	bf_log("[LOG] Sent handshake.\n");
	if(send(socketfd, hs, hs_len, 0) == -1)
	{
		perror("send");
		rv = -1;
		goto cleanup;
	}	

	/*********** RECEIVE HANDSHAKE + BITFIELD + HAVE's (possibly) ***********/
	rv = receive_msg_hs(socketfd, &recvfd, &recvd_msg, &len);
	bf_log("[LOG] rv from receive_msg: %d.\n", rv);
        if(rv == RECV_ERROR)
        {
		goto cleanup;
        }
        if(rv != RECV_TO)
        {
		bf_log("[LOG] Received handshake response of length %d. Going to process it now.\n", len);
		process_msgs(recvd_msg, len, 1, &peer_status);
		bf_log("[LOG] Done pocessing handshake.\n");
        }
        if(recvd_msg)
        {
		free(recvd_msg);
                recvd_msg = NULL;
        }	

	do
	{
		rv = receive_msg(socketfd, &recvfd, &recvd_msg, &len);
		bf_log("[LOG] rv from receive_msg: %d.\n", rv);
		if(rv == RECV_ERROR)
		{
			goto cleanup;
		}
		if(rv != RECV_TO)
		{
			bf_log("[LOG] Received next msg after HS. Len: %d. Goinf to process it now.\n", len);
			process_msgs(recvd_msg, len, 0, &peer_status);
		}
		if(recvd_msg)
		{
			free(recvd_msg);
			recvd_msg = NULL;
		}
	} while(rv != RECV_TO);

	bf_log("[LOG] Finished receiving until timeout. Checking if peer has any pieces.\n");
	// check if this peer has any pieces we don't have and then send interested.
	if(!peer_status.has_pieces)
	{
		bf_log("** Peer has no pieces, so not sending interested.\n");
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

	bf_log("[LOG] Sent interested message. Receiving response now.\n");
	/******** RECEIVE RESPONSE TO INTERESTED *************/
	while(!peer_status.unchoked)
	{
		// TODO: refactor this set of lines into it's own method. it's repeated whenever we want to receive messages.
		rv = receive_msg(socketfd, &recvfd, &recvd_msg, &len);
		bf_log("[LOG] rv from receive_msg: %d.\n", rv);
        	if(rv == RECV_ERROR)
        	{
			rv = -1;
                	goto cleanup;
        	}
		if(rv == RECV_TO)
		{
			rv = -1;
			goto cleanup;
		}

		bf_log("[LOG] Received response for INTERESTED message. Going to process it now.\n");
		process_msgs(recvd_msg, len, 0, &peer_status);
		if(recvd_msg)
		{
			free(recvd_msg);
			recvd_msg = NULL;
		}
	}
	rv = 0;
	bf_log("[LOG] Peer has unchoked us.\n");	
	// if here then pieces must be populated and we're unchoked too.
	// TODO: start requesting pieces	
	rv = get_pieces(socketfd, &peer_status);

cleanup:
	bf_log(" ------------------------------------ FINISH: TALK_TO_PEER  ----------------------------------------\n");	

	bf_log("[LOG] In cleanup.\n");
	if(socketfd > 0)
	{
		bf_log("[LOG] Closing socket.\n");
		close(socketfd);
	}
	if(hs)
	{
		bf_log("[LOG] Freeing HS.\n");
		free(hs);
		hs = NULL;
	}
	if(recvd_msg)
        {
		bf_log("[LOG] Freeing recvd_msg.\n");
		free(recvd_msg);
                recvd_msg = NULL;
        }
	return (void *)rv;
}

int receive_msg_hs(int socketfd, fd_set *recvfd, uint8_t **msg, int *len)
{
        int rv;
	uint8_t *curr;

        rv = get_len_hs(socketfd, recvfd, len);
        if(rv != RECV_OK)
        {
                bf_log(  "[LOG] inside receive_msg_hs: get_len_hs didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                goto cleanup;
        }

        *msg = malloc(*len + 1);
	curr = *msg;
	*curr = (uint8_t)(*len - 8 - 20 - 20);
	curr++;
        rv = receive_msg_for_len(socketfd, recvfd, *len, curr);
        if(rv != RECV_OK)
        {
                bf_log(  "[ERROR] inside receive_msg_hs: receive_msg_for_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                rv = RECV_ERROR; // even if it is timeout, at this stage it means error.
                goto cleanup;
        }

cleanup:
	bf_log("---------------------------------------- FINISH:  TALK_TO_PEER ----------------------------------------\n");
        return rv;
}

int receive_msg(int socketfd, fd_set *recvfd, uint8_t **msg, int *len)
{
	bf_log("++++++++++++++++++++ START:  RECEIVE_MSG+++++++++++++++++++++++\n");
	int rv, temp;
	uint8_t *curr;

	rv = get_len(socketfd, recvfd, len);
	if(rv != RECV_OK)
	{
		bf_log(  "[LOG] inside receive_msg: get_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
		goto cleanup;
	}

	*msg = malloc(*len + 4);
	curr = *msg;
	temp = htonl(*len);
	memcpy(curr, &temp, 4);
	curr += 4;
	rv = receive_msg_for_len(socketfd, recvfd, *len, curr);
	if(rv != RECV_OK)
	{
		bf_log(  "[ERROR] inside receive_msg: receive_msg_for_len didn't return RECV_OK. rv = %d (0=OK; 1=TO; -1=ERROR)\n", rv);
                rv = RECV_ERROR; // even if it is timeout, at this stage it means error.
		goto cleanup;
	}
	*len += 4;

cleanup:
	bf_log(" -------------------------------------- FINISH: RECEIVE_MSG  ----------------------------------------\n");
	return rv;
}

int get_len(int socketfd, fd_set *recvfd, int *len)
{
	bf_log("++++++++++++++++++++ START:  GET_LEN +++++++++++++++++++++++\n");
	
	int rv;
	uint8_t *curr = (uint8_t *)len;

	rv = receive_msg_for_len(socketfd, recvfd, 4, curr);	
	*len = ntohl(*len);	

	bf_log("---------------------------------------- FINISH:  GET_LEN ----------------------------------------\n");
	return rv;
}

int get_len_hs(int socketfd, fd_set *recvfd, int *len)
{
	bf_log("++++++++++++++++++++ START:  GET_LEN_HS +++++++++++++++++++++++\n");
        int rv;
	uint8_t *p_name_len = malloc(1);

        rv = receive_msg_for_len(socketfd, recvfd, 1, p_name_len);

        *len = *p_name_len + 8 + 20 + 20;

	bf_log("---------------------------------------- FINISH:  GET_LEN_HS ----------------------------------------\n");
        return rv;
}

int receive_msg_for_len(int socketfd, fd_set *recvfd, int len, uint8_t *msg)
{
	bf_log("++++++++++++++++++++ START:  RECEIVE_MSG_FOR_LEN +++++++++++++++++++++++\n");
	
	if(len == 0)
	{
		return RECV_OK;
	}
	int r_bytes, rv;
        uint8_t *curr = msg;
	struct timeval tv;

	tv.tv_sec = 10;
        tv.tv_usec = 0;
        // TODO: the for-loop to keep receiving until we have received the 4 bytes which specify length.
        rv = select(socketfd + 1, recvfd, NULL, NULL, &tv);
        bf_log("[LOG] receive_msg_for_len: value of 'rv' after select: %d (1=OK; 0=timeout; -1=error)\n", rv);

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
			bf_log("[ERROR]receive_msg_for_len: Peer closed connection");
                        return RECV_ERROR;
                }
		bf_log("[LOG] receive_msg_for_len(): received %d bytes when attempted to receive %d bytes.\n", rv, len - r_bytes); 
        }

	bf_log("---------------------------------------- FINISH:  RECEIVE_MSG_FOR_LEN ----------------------------------------\n");
        return RECV_OK;
}
		
uint8_t *compose_handshake(uint8_t *info_hash, uint8_t *our_peer_id, int *len)
{
	bf_log("++++++++++++++++++++ START:  COMPOSE_HANDSHAKE +++++++++++++++++++++++\n");
	
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

	bf_log("---------------------------------------- FINISH:  COMPOSE_HANDSHAKE ----------------------------------------\n");
	return hs;
}

uint8_t *compose_interested(int *len)
{
	bf_log("++++++++++++++++++++ START:  COMPOSE_INTERESTED +++++++++++++++++++++++\n");
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

	bf_log("---------------------------------------- FINISH:  COMPOSE_INTERESTED ----------------------------------------\n");
	return msg;
}

uint8_t extract_msg_id(uint8_t *response)
{
	bf_log("++++++++++++++++++++ START:  EXTRACT_MSG_ID +++++++++++++++++++++++\n");
	if((*(int *)response) == 0) //if length is zero then keep alive msg
	{
		return KEEP_ALIVE_MSG_ID;
	}
	uint8_t msg_id = response[4];

	bf_log("---------------------------------------- FINISH:  EXTRACT_MSG_ID ----------------------------------------\n");
	return msg_id;
}

int process_msgs(uint8_t *msgs, int len, int has_hs, struct pwp_peer *peer)
{
	bf_log("++++++++++++++++++++ START:  PROCESS_MSGS +++++++++++++++++++++++\n");
	if(!msgs)
	{
		bf_log(  "ERROR: process_msgs: MSGS is null.\n");
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
		bf_log("*-*-* Got HANDSHAKE message.\n");
	}

	while(len > 0)
	{
		temp = curr;
		switch(extract_msg_id(temp))
		{
			case BITFIELD_MSG_ID:
				// TODO: populate global stats collection
				bf_log("*-*-* Got BITFIELD message.\n");
				process_bitfield(temp, peer);
				peer->has_pieces = 1;
				break;
			case UNCHOKE_MSG_ID:
				peer->unchoked = 1;
				bf_log("*-*-* Got UNCHOKE message.\n");
				break;
			// TODO: other cases
			case CHOKE_MSG_ID:
				peer->unchoked = 0;
				bf_log("*-*-* Got CHOKE message.\n");
				break;
			case INTERESTED_MSG_ID:
				// TODO:
				bf_log("*-*-* Got INTERESTED message.\n");
				break;
			case NOT_INTERESTED_MSG_ID:
				// TODO:
				bf_log("*-*-* Got NOT INTERESTED message.\n");
				break;
			case HAVE_MSG_ID:
				// TODO:
				bf_log("*-*-* Got HAVE message.\n");
				process_have(temp, peer);
				peer->has_pieces = 1;
				break;
			case REQUEST_MSG_ID:
				// TODO:
				bf_log("*-*-* Got REQUEST message.\n");
				break;
			case PIECE_MSG_ID:
				// TODO:
				bf_log("*-*-* Got PIECE message.\n");
				break;
			case CANCEL_MSG_ID:
				// TODO:
				bf_log("*-*-* Got CANCEL message.\n");
				break;
			case KEEP_ALIVE_MSG_ID:
			        // TODO:
				bf_log("*-*-* Got KEEP ALIVE message.\n");
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
	bf_log("---------------------------------------- FINISH:  PROCESS_MSGS----------------------------------------\n");
	return rv;
}

int get_pieces(int socketfd, struct pwp_peer *peer)
{
	bf_log("++++++++++++++++++++ START:  GET_PIECES +++++++++++++++++++++++\n");
	int count, rv = 0;
	FILE *savedfp = NULL;

	/* -X-X-X- CRITICAL REGION START -X-X-X- */
        pthread_mutex_lock(&g_downloaded_pieces_mutex);

        count = g_downloaded_pieces;

        pthread_mutex_unlock(&g_downloaded_pieces_mutex);
        /* -X-X-X- CRITICAL REGION END -X-X-X- */

        if(count >= PIECES_TO_DOWNLOAD)
        {
                bf_log("[LOG] get_pieces(): Not downloading any further pieces as the desired no of pieces have been downloaded.\n");
                goto cleanup;
        }

	int idx = choose_random_piece_idx(peer->peer_id);

	savedfp = fopen(g_saved_filepath, "r+");
        if(!savedfp)
        {
                bf_log("[ERROR] get_pieces(): Failed to open saved file. Aborting this thread.\n");
                rv = -1;
		goto cleanup;
        }
	
	while(idx != -1) // idx is -1 when no piece to download is found
	{
		bf_log("[LOG] Chose random piece index: %d\n", idx);
		rv = download_piece(idx, socketfd, savedfp, peer);

		/* -X-X-X- CRITICAL REGION START -X-X-X- */
		pthread_mutex_lock(&g_pieces_mutexes[idx]);

		if(rv == 0)
		{
			g_pieces[idx].status = PIECE_STATUS_COMPLETE;
		}
		else
		{
			g_pieces[idx].status = PIECE_STATUS_AVAILABLE;
		}

		pthread_mutex_unlock(&g_pieces_mutexes[idx]);
		/* -X-X-X- CRITICAL REGION END -X-X-X- */

		/* -X-X-X- CRITICAL REGION START -X-X-X- */
                pthread_mutex_lock(&g_downloaded_pieces_mutex);

                count = g_downloaded_pieces;

                pthread_mutex_unlock(&g_downloaded_pieces_mutex);
                /* -X-X-X- CRITICAL REGION END -X-X-X- */

                if(count >= PIECES_TO_DOWNLOAD)
                {
                        bf_log("[LOG] get_pieces(): Not downloading any further pieces as the desired no of pieces have been downloaded.\n");

                        break;
                }	

		idx = choose_random_piece_idx(peer->peer_id);
	}

cleanup:
	bf_log("---------------------------------------- FINISH:  GET_PIECES----------------------------------------\n");
	if(savedfp)
	{
		bf_log("[LOG] get_pieces(): closing saved file pointer.\n");
		fclose(savedfp);
	}
	return rv;	
}

int download_piece(int idx, int socketfd, FILE *savedfp, struct pwp_peer *peer)
{
	bf_log("++++++++++++++++++++ START:  DOWNLOAD_PIECE +++++++++++++++++++++++\n");
    /* TODO:
    1. Calculate number of blocks in this piece (2^14 (16384) bytes per block )
    2. malloc an array 'blocks' of struct pwp_block for this piece 
    3. initialise each pwp_block in the blocks array
    LOOP:
        4. create three REQUEST messages for three blocks which don't have status DOWNLOADED. if no such block then break the loop
	5. keep a outstanding_requests counter and initialise it to three.
        6. receive PIECE msgs and save data (write different method for piece messages, not receive_msg)
        7. keep receiving while decrementing outstanding_reuests, until either outstanding_requests becomes zero or  timeout happens.
        8. update 'blocks' array
        9. go to step 4
    END OF LOOP
    10. compute sha1 of downloaded piece
    11. verify the sha1 with the one in announce file. (or metada file?)
    12. return 0 or -1 accordingly.
    */

	int i, len, rv;
	uint8_t *requests;
	struct pwp_block received_block;

	rv = 0;
// No 1 above:
	int num_of_blocks = g_piece_length / BLOCK_LEN;
	int bytes_in_last_block = g_piece_length % BLOCK_LEN;

	if(bytes_in_last_block)
	{
		num_of_blocks += 1;
	}
// No 2 above:
	struct pwp_block *blocks = malloc(num_of_blocks * sizeof(struct pwp_block));
// No 3 above:
	struct pwp_block *curr = blocks;
	for(i = 0; i<num_of_blocks; i++)
	{
		curr[i].offset = i * BLOCK_LEN;
		curr[i].length = BLOCK_LEN;
		curr[i].status = BLOCK_STATUS_NOT_DOWNLOADED;
	}
	if(bytes_in_last_block)
	{
		curr[num_of_blocks-1].length = bytes_in_last_block;
	}

// No 4 to p above:
	requests = prepare_requests(idx, blocks, num_of_blocks, BLOCK_REQUESTS_COUNT, &len);
	int outstanding_requests = BLOCK_REQUESTS_COUNT;
	while(requests)
	{
		if(send(socketfd, requests, len, 0) == -1)
        	{
		        perror("send");
		        rv = -1;
		        goto cleanup;
        	}
		bf_log("[LOG] Sent piece requests. Receiving response now.\n");
		while(outstanding_requests && (rv = download_block(socketfd, idx, savedfp,  &received_block, peer)) == RECV_OK)
		{
			bf_log("[LOG] Successfully downloaded one block :)\n");
			// calculate block index
			i = received_block.offset/BLOCK_LEN;
			if(i >=	num_of_blocks)
			{
				bf_log("[ERROR] download_piece(): block idx (%d) returned >= num_of_blocks (%d).\n", i, num_of_blocks);
				rv = -1;
				goto cleanup;
			}	
			blocks[i].status = received_block.status;
			outstanding_requests--;
		}
		
		free(requests);
		requests = NULL;
		requests = prepare_requests(idx, blocks, num_of_blocks, BLOCK_REQUESTS_COUNT, &len);
		outstanding_requests = BLOCK_REQUESTS_COUNT;
	}
	free(requests);
        requests = NULL;

	// TODO: HOW do we take care of length of last piece! it will usually be less than g_piece_length.
	uint8_t *piece_data = (uint8_t *)malloc(g_piece_length);	

	// flush file buffer before reading the chunk. this is imporant because otherwise sha1 to be computed will be incorrect.
	fflush(savedfp);

	// TODO: this can be made to use savedfp rather than openinig the file separately. Take caution that util_read_file_chunk 
	//	then doesn't change the position of file pointer so as to write at incorrect pos when downloading next piece.	
	if(util_read_file_chunk(g_saved_filepath, idx *  g_piece_length, g_piece_length, piece_data) != 0)
	{
		bf_log("[ERROR] download_piece(): Faile to read piece number %d from file, therefore unable to verify SHA1 hash.\n", idx );
		free(piece_data);
		piece_data = NULL;
                rv = -1;
                goto cleanup;
	}
	
	uint8_t *piece_hash = sha1_compute(piece_data, g_piece_length);

	// compute the index of first byte of the actual piece hash inside the global piece hashes string
	i = idx * 20;
	uint8_t *actual_sha1 = g_piece_hashes + i;
	for(i=0; i<20; i++)
	{
		if(piece_hash[i] != actual_sha1[i])
		{
			bf_log("[ERROR] download_piece(): Verification of SHA1 piece number %d failed.\n", idx );
	                bf_log_binary("  > Computed piece hash: ", piece_hash, 20);
			bf_log_binary("  > Actual piece hash: ", actual_sha1, 20);
			free(piece_hash);
        	        piece_hash = NULL;
                	rv = -1;
                	goto cleanup;
		}
	}

	bf_log("[LOG] download_piece(): Successfulle verified SHA1 of piece at index %d.\n", idx);

	free(piece_hash);
	piece_hash = NULL;	

	/* -X-X-X- CRITICAL REGION START -X-X-X- */
        pthread_mutex_lock(&g_downloaded_pieces_mutex);

        g_downloaded_pieces++;

        pthread_mutex_unlock(&g_downloaded_pieces_mutex);
        /* -X-X-X- CRITICAL REGION END -X-X-X- */

        bf_log("[LOG] *-*-*-*- Downloaded piece!! Piece index: %d.\n", idx);

cleanup:
	bf_log("---------------------------------------- FINISH:  DOWNLOAD_PIECE ----------------------------------------\n");
	if(requests)
	{
		free(requests);
	}
	return rv;
} 

int download_block(int socketfd, int expected_piece_idx, FILE *savedfp, struct pwp_block *block, struct pwp_peer *peer)
{

	bf_log("++++++++++++++++++++ START:  DOWNLOAD BLOCK +++++++++++++++++++++++\n");
	uint8_t *msg, *temp;
	int rv, len;
	uint8_t msg_id;
	fd_set recvfd;
	
	temp = NULL;
	msg = NULL;
	msg_id = 255;
	FD_ZERO(&recvfd);
	FD_SET(socketfd, &recvfd);
	msg = malloc(MAX_DATA_LEN);
	// NOTE: cannot call receive_msg method above because piece msg will be too long to hold in memory.
	// TODO: create separate method that handles this scenario as well as receive_msg.
	while(msg_id != PIECE_MSG_ID)
	{
		bf_log("[LOG] Going to get length of message. calling receive_msg_for_len().\n");
		rv = receive_msg_for_len(socketfd, &recvfd, 4, msg); 
		
		if(rv != RECV_OK)
		{
			bf_log(  "[ERROR] download_block: failed to receive length. rv = %d (0=OK, 1=timeout, -1=error).\n", rv);
			goto cleanup;
		}
		if(*((int *)msg) == 0)
		{
			bf_log("[LOG] download_block: received KEEP_ALIVE message.\n");
			msg_id = KEEP_ALIVE_MSG_ID;
			continue;
		}
		len = ntohl(*((int *)msg));
		
		rv = receive_msg_for_len(socketfd, &recvfd, 1, msg); 
		if(rv != RECV_OK)
		{
			bf_log(  "[ERROR] download_block: failed to receive message type. rv = %d (0=OK, 1=timeout, -1=error).\n", rv);
			rv = RECV_ERROR;
			goto cleanup;
		}
		msg_id = *msg;
		if(msg_id != PIECE_MSG_ID)
		{
			bf_log("[LOG] download_block: the message is not PIECE message. Message Id: %d; Message Length (excluding 4 bytes for length): %d\n", msg_id, len);
			temp = malloc(len + 4);
			rv = receive_msg_for_len(socketfd, &recvfd, len - 1, msg); 
			if(rv != RECV_OK)
			{
				bf_log("[ERROR] download_block: got a problem reading message. Message Id: %d\n", msg_id);
				rv = RECV_ERROR;
				goto cleanup;
			}
			len = htonl(len);
			memcpy(temp, &len, 4);
			memcpy(temp + 4, &msg_id, 1);
			memcpy(temp + 5, msg, ntohl(len) - 1);			
			process_msgs(temp, len, 0, peer);
			free(temp);
			temp = NULL;
		}
	}
	bf_log("[LOG] Received PIECE message!! Going to process it now.\n");
	// TODO: process the piece message. here len = num of data bytes in block + 4(piece idx) + 4(block offset) + 1 (for msg id) & msg_id = PIECE_MSG_ID.
	//	have a global file descriptor to the file that already has the total memory required
	//	using piece length and idx and block offset calculate position of bytes to store inside that file
	//	save the bytes in file and mark that block's status as BLOCK_DOWNLOADED
	int piece_idx, block_offset, remaining;
	remaining = len - 9; // remaining is no of bytes in this block yet to be downloaded
	block->length = remaining;

	rv = receive_msg_for_len(socketfd, &recvfd, 4, msg);
        if(rv != RECV_OK)
        {
		bf_log(  "[ERROR] receive_and_process_piece_msgs(): Failed to receive piece index.\n");
		rv = RECV_ERROR;
		goto cleanup;
        }	
	piece_idx = ntohl(*((int *)msg));

	if(piece_idx != expected_piece_idx)
	{
		bf_log(  "[ERROR] receive_and_process_piece_msgs(): Piece index not as expected. Expected %d, received %d.\n", expected_piece_idx, piece_idx);
                rv = RECV_ERROR;
		goto cleanup;
	}

	rv = receive_msg_for_len(socketfd, &recvfd, 4, msg);
        if(rv != RECV_OK)
        {
                bf_log(  "[ERROR] receive_and_process_piece_msgs(): Failed to receive block offset.\n");
                rv = RECV_ERROR;
		goto cleanup;
        }       
        block_offset = ntohl(*((int *)msg));
	block->offset = block_offset;
	bf_log("[LOG] *-*-*- Going to receive piece_idx: %d, block_offset: %d, block length: %d.\n", piece_idx, block_offset, remaining);

	/* -X-X-X- CRITICAL REGION START (for saved file) -X-X-X- */
	// TODO: create a separate file pointer in each thread. that way this locking won't be required. 
	//	that is because each file pointer will be writing in separate locations of the file.
	//	the aim is to completely remove g_savedfp and g_savedfp_mutex.
	// pthread_mutex_lock(&g_savedfp_mutex);

	fseek(savedfp, (piece_idx * g_piece_length) + block_offset, SEEK_SET);
	len = 512; //use len as buffer for following loop	

	int bytes_saved = 0;
	while(remaining)
	{
		if(remaining < len)
		{
			len = remaining;
		}

		rv = receive_msg_for_len(socketfd, &recvfd, len, msg);
        	if(rv != RECV_OK)
	        {
                	bf_log(  "[ERROR] receive_and_process_piece_msgs(): Failed to receive block data. bytes_saved= %d.\n", bytes_saved);
			rv = RECV_ERROR;
        	        goto cleanup;
	        }
		// TODO: IMPORTANT, this method may not write all len bytes to the file. MUST check the value returned by fwrite here.
	        fwrite(msg, 1, len, savedfp);

		remaining -= len;
		bytes_saved += len;
	}

	// pthread_mutex_unlock(&g_savedfp_mutex);
	/* -X-X-X- CRITICAL REGION END (for saved file) -X-X-X- */

	// if here then the block must have been successfully downloaded. update the block struct.
	block->status = BLOCK_STATUS_DOWNLOADED;

cleanup:
	bf_log(" ---------------------------------------- FINISHED: DOWNLOAD BLOCK  ----------------------------------------\n");
	if(msg)
	{
		free(msg);
	}

	if(temp)
	{
		free(temp);
	}
	return rv;
}

uint8_t *prepare_requests(int piece_idx, struct pwp_block *blocks, int num_of_blocks, int max_requests, int *len)
{
	bf_log("++++++++++++++++++++ START:  PREPARE_REQUESTS +++++++++++++++++++++++\n");
	
	int i, count;
	int msg_len = 17; // 17 = length of request message
	uint8_t *requests = malloc(msg_len * max_requests); 
	uint8_t *curr;
	// find up to max_request blocks which are not downloaded.
	count = 0;
	*len = 0;
	for(i=0; i<num_of_blocks; i++)
	{
		if(blocks[i].status == BLOCK_STATUS_NOT_DOWNLOADED)
		{
			curr = compose_request(piece_idx, blocks[i].offset, blocks[i].length, &msg_len);
			memcpy(requests+(count * msg_len), curr, msg_len);
			free(curr);
			*len += msg_len;
			count++;
			if(count == max_requests)
			{
				break;
			}
		}
	}
	if(count == 0)
	{
		free(requests);
		return NULL;
	}
	
	bf_log("---------------------------------------- FINISH:  PREPARE_REQUESTS  ----------------------------------------\n");
	return requests;
}
uint8_t *compose_request(int piece_idx, int block_offset, int block_length, int *len)
{
	bf_log("++++++++++++++++++++ START:  COMPOSE_REQUESTS +++++++++++++++++++++++\n");
	*len = 17; // 4 (msg len) + 1 (msg id) + 4 (piece idx) + 4 (block offset) + 4 (block length)
	uint8_t *msg = malloc(*len); 
	int temp = htonl(13);
	uint8_t msg_id = REQUEST_MSG_ID;
	memcpy(msg, &temp, 4);
	memcpy(msg+4, &msg_id, 1);
	temp = htonl(piece_idx);
	memcpy(msg+5, &temp, 4);
	temp = htonl(block_offset);
	memcpy(msg+9, &temp, 4);
	temp = htonl(block_length);
	memcpy(msg+13, &temp, 4);
	
	bf_log("---------------------------------------- FINISH:  COMPOSE_REQUESTS ----------------------------------------\n");
	return msg;
}

int process_bitfield(uint8_t *msg, struct pwp_peer *peer)
{
	bf_log("++++++++++++++++++++ START:  PROCESS_BITFIELD +++++++++++++++++++++++\n");
    uint8_t *curr = msg;
    int i, j, rv, idx;
    uint8_t bits, mask;
      
    rv = 0;
    // read bitfield, parse it and populate pieces array accordingly.
    int len = ntohl(*((int *)curr));
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
                if(idx >= g_num_of_pieces)
                {
                    bf_log("[ERROR] process_bitfield(): Bitfield has more bits set than there are number of pieces.\n");
                    rv = -1;
                    // TODO: Reset all pieces that were set to available for this particular peer.
                    goto cleanup;
                }
                if(g_pieces[idx].status != PIECE_STATUS_COMPLETE)
                {
                    g_pieces[idx].status = PIECE_STATUS_AVAILABLE;
		
		    linked_list_add(&g_pieces[idx].peers, peer);	
                }
            }
            mask = mask / 2;
        }
    }

cleanup:
	bf_log("---------------------------------------- FINISH:  PROCESS_BITFIELD ----------------------------------------\n");
    return rv;
}
  
int process_have(uint8_t *msg, struct pwp_peer *peer)
{
	bf_log("++++++++++++++++++++ START:  PROCESS_HAVE +++++++++++++++++++++++\n");
    int rv = 0;
    uint8_t *curr = msg;
    int idx = ntohl((int)(*(curr+5)));
      
    if(g_pieces[idx].status != PIECE_STATUS_COMPLETE)
    {
        g_pieces[idx].status = PIECE_STATUS_AVAILABLE;
        linked_list_add(&g_pieces[idx].peers, peer);
    }

	bf_log("---------------------------------------- FINISH:  PROCESS_HAVE ----------------------------------------\n");
    return rv;
} 

int choose_random_piece_idx(uint8_t *peer_id)
{
	bf_log("++++++++++++++++++++ START:  CHOOSE_RANDOM_PIECE_IDX +++++++++++++++++++++++\n");
    int i, r, random_piece_idx;
      
    random_piece_idx = -1;
    srand(time(NULL));
      
    for(i=0; i<10; i++) // 10 attempts at getting a random available piece
    {
        r = rand() % g_num_of_pieces;
	/*-X-X-X- START OF CRITICAL REGION  -X-X-X-*/
	bf_log("[LOG] choose_random_piece_idx(): Found random number. Going to lock g_piece_mutexes[%d].\n", r);
	pthread_mutex_lock(&g_pieces_mutexes[r]);
	bf_log("[LOG] choose_random_piece_idx(): Successfully locked g_piece_mutexes[%d].\n", r);

        if(linked_list_contains_peer_id(g_pieces[r].peers, peer_id) && (g_pieces[r].status == PIECE_STATUS_AVAILABLE))
        {
            random_piece_idx = r;
	    g_pieces[r].status = PIECE_STATUS_STARTED; // this has to be done in the same critical region as when selecting it.
							// otherwise two threads can choose same random piece.
	    bf_log("[LOG] choose_random_piece_idx(): Found RANDOM available piece. Going to release g_piece_mutexes[%d].\n", r);
	    pthread_mutex_unlock(&g_pieces_mutexes[r]);
            break;
        }

	bf_log("[LOG] choose_random_piece_idx(): Random piece index not available. Going to release g_piece_mutexes[%d].\n", r);
	pthread_mutex_unlock(&g_pieces_mutexes[r]);
	/*-X-X-X- END OF CRITICAL REGION  -X-X-X-*/
    }
      
    // if no piece found after random attempts then go sequentially
    if(random_piece_idx == -1)
    {
        for(i=0; i<g_num_of_pieces; i++)
        {
	    /*-X-X-X- START OF CRITICAL REGION  -X-X-X-*/
	    bf_log("[LOG] choose_random_piece_idx(): Sequential search. Going to lock g_piece_mutexes[%d].\n", i);
            pthread_mutex_lock(&g_pieces_mutexes[i]);
         
	   if(linked_list_contains_peer_id(g_pieces[i].peers, peer_id) && (g_pieces[i].status == PIECE_STATUS_AVAILABLE))
           {
                random_piece_idx = i;
		g_pieces[i].status = PIECE_STATUS_STARTED; // this has to be done in the same critical region as when selecting it.
                                                        // otherwise two threads can choose same random piece.
		bf_log("[LOG] choose_random_piece_idx(): Found sequential available piece index. Going to release g_piece_mutexes[%d].\n", i);
		pthread_mutex_unlock(&g_pieces_mutexes[i]);
                break;
           }
	   bf_log("[LOG] choose_random_piece_idx(): Sequential piece index is not available. Going to release g_piece_mutexes[%d].\n", i);
	   pthread_mutex_unlock(&g_pieces_mutexes[i]);
           /*-X-X-X- END OF CRITICAL REGION  -X-X-X-*/
        }
    }
      
	bf_log("---------------------------------------- FINISH:  CHOOSE_RANDOM_PIECE_IDX  ----------------------------------------\n");
    return random_piece_idx;
}

int are_same_peers(uint8_t *peer_id1, uint8_t *peer_id2)
{
	// TODO: perform bounds checking
//	bf_log("++++++++++++++++++++ START:  ARE_SAME_PEERS +++++++++++++++++++++++\n");

	int rv = 1; // default: are same peers
	int i;
	
	for(i=0; i<20; i++)
	{
		if(peer_id1[i] != peer_id2[i])
		{
//			bf_log("[LOG] are_same_peers(): peers are not the same.\n");
			rv = 0;
			break;
		}
	}

cleanup:
//	bf_log("---------------------------------------- FINISH:  ARE_SAME_PEERS ----------------------------------------\n");
	return rv;
}

void linked_list_add(struct pwp_peer_node **head, struct pwp_peer *peer)
{
//	bf_log("++++++++++++++++++++ START:  LINKED_LIST_ADD +++++++++++++++++++++++\n");
	// special case of head being null
	if(*head == NULL)
	{
		*head = malloc(sizeof(struct pwp_peer_node));
		(*head)->peer = peer;
		(*head)->next = NULL;
		return;
	}

	// if here then head must not be null
	struct pwp_peer_node *curr = *head;

	while(curr->next != NULL)
	{
		curr = curr->next;
	}
	curr->next = malloc(sizeof(struct pwp_peer_node));
	curr = curr->next;
	curr->peer = peer;
	curr->next = NULL;
//	bf_log("---------------------------------------- FINISH:  LINKED_LIST_ADD ----------------------------------------\n");
}

int linked_list_contains_peer_id(struct pwp_peer_node *head, uint8_t *peer_id)
{
//	bf_log("++++++++++++++++++++ START:  LINKED_LIST_CONTAINS_PEER_ID +++++++++++++++++++++++\n");
	int rv = 0;

	while(head)
	{
		if(are_same_peers(head->peer->peer_id, peer_id))
		{
			rv = 1;
			break;
		}

		head = head->next;
	}

//	bf_log("---------------------------------------- FINISH:  LINKED_LIST_CONTAINS_PEER_ID ----------------------------------------\n");
	return rv;
}

void linked_list_free(struct pwp_peer_node **head)
{
//	bf_log("++++++++++++++++++++ START:  LINKED_LIST_FREE +++++++++++++++++++++++\n");
        
	struct pwp_peer_node *curr, *temp;
	curr = *head;
	while(curr)
	{
		temp = curr;
		curr = curr->next;
		free(temp);
	}
	*head = NULL;

//        bf_log("---------------------------------------- FINISH:  LINKED_LIST_FREE ----------------------------------------\n");
}

int initialise_pieces(struct pwp_piece *pieces, const char *path_to_resume_file)
{
	int rv = 0;
	int i, j;
	uint8_t mask;
	uint8_t *resume_data = NULL;
	int resume_len;

	if(util_read_whole_file(path_to_resume_file, &resume_data, &resume_len) != 0)
	{
		rv = -1;
		bf_log("[ERROR] initialise_pieces(): Failed to read resume file '%s'.\n", path_to_resume_file);
		goto cleanup;
	}

	for(i = 0; i < resume_len; i++)
	{
		for(j = 0; j < 8; j++)
		{
			mask = 0x80 >> j;
			if(resume_data[i] & mask)
			{
				pieces[i*8 + j].status = PIECE_STATUS_COMPLETE;
			}
			else
			{
				pieces[i*8 + j].status = PIECE_STATUS_NOT_AVAILABLE;
			}
		}
	}

cleanup:
	if(resume_data)
	{
		free(resume_data);
	}

	return rv;
}

int update_resume_file(const char *path_to_resume_file, int downloaded_piece_index)
{
	int rv = -1;
	int byte_index = downloaded_piece_index / 8;
	uint8_t resume_byte;
	uint8_t mask;
// TODO: acquire lock on g_resume_mutexes[byte_index]
	/*-X-X-X- START OF CRITICAL REGION  -X-X-X-*/
        bf_log("[LOG] update_resume_file(): Going to lock g_resume_mutexes[%d].\n", byte_index);
        pthread_mutex_lock(&g_resume_mutexes[byte_index]);
        bf_log("[LOG] update_resume_file(): Successfully locked g_resume_mutexes[%d].\n", byte_index);

	if(util_read_file_chunk(path_to_resume_file, byte_index, 1, &resume_byte) == -1)
	{
		// TODO: free the corresponding g_resume_mutexes here	
		pthread_mutex_unlock(&g_resume_mutexes[byte_index]);	
		rv = -1;
		bf_log("[ERROR] update_resume_file(): Failed to read the correct byte from the resume file '%s'. Released g_resume_mutexes[%d].\n", path_to_resume_file, byte_index);
		goto cleanup;
	}
	mask = 0x80 >> (downloaded_piece_index % 8);
	resume_byte |= mask;

	FILE *resumefp = fopen(path_to_resume_file, "r+");
	fseek(resumefp, byte_index, SEEK_SET);
	fwrite(&resume_byte, 1, 1, resumefp);
	fclose(resumefp);
	resumefp = NULL;

// TODO: release lock on g_resume_mutexes[byte_index]
	bf_log("[LOG] Going to release g_resume_mutexes[%d].\n", byte_index);
	pthread_mutex_unlock(&g_resume_mutexes[byte_index]);

cleanup:
	if(resumefp)
	{
		fclose(resumefp);
	}
	return rv;
}

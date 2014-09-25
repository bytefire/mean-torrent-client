#ifndef PWP_H
#define PWP_H

#pragma once

#include<stdint.h>
#include<pthread.h>

#include "bencode.h"

struct pwp_peer
{
        uint8_t peer_id[20];
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
	long int piece_length; // we need to store this for each piece because the last piece will have a different size from the rest.
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
int initialise_pieces(struct pwp_piece *pieces, long int total_length, long int num_of_pieces, long int piece_length, const char *path_to_resume_file);
int update_resume_file(const char *path_to_resume_file, int downloaded_piece_index);

int pwp_start(char *md_filepath, char *saved_filepath, char *resume_filepath);

int extract_next_peer(bencode_t *list_of_peers, char **ip, uint16_t *port);

#endif // PWP_H

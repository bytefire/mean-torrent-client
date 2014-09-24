#ifndef PEERS_H
#define PEERS_H

#pragma once

#include<stdint.h>

#include "bencode.h"

struct peer
{
	uint8_t ip[4];
	uint16_t port;
	
	struct peer *next;
};

int peers_extract(char *contents, int len, struct peer **head);

int peers_extract_from_file(char *filename, struct peer **head);

void peers_free(struct peer *head);

/*
Format of metadata file:
------------------------

Whole file is one bencoded dictionary with following keys.

1. info_hash: 20 byte info hash
2. our_peer_id: 20 byte our peer id
3. total_length (integer): total size of the file to be downloaded
4. num_of_pieces (integer): total number of pieces
5. piece_length (integer): length of each piece in bytes
6. piece_hashes: sha1 hashes of all the pieces.
7. peers (list of dictionaries): each element is a dictionary with following keys.
	a. ip
	b. port
*/
void peers_create_metadata(char *announce, int len, uint8_t *info_hash, uint8_t *piece_hashes, uint8_t *our_peer_id, long int total_length, long int num_of_pieces, long int piece_length, const char *metadata_filename);

#endif // PEERS_H

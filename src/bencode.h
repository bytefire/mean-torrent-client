#ifndef BENCODE_H_
#define BENCODE_H_

enum
{
	// init state
	BENCODE_TOK_NONE,
	// a list
	BENCODE_TOK_LIST,
	// length of dictionary key
	BENCODE_TOK_DICT_KEYLEN,
	// dictionary key
	BENCODE_TOK_DICT_KEY,
	// dictionary key value
	BENCODE_TOK_DICT_VAL,
	// integer
	BENCODE_TOK_INT,
	// length of string
	BENCODE_TOK_STR_LEN,
	// string
	BENCODE_TOK_STR,
	// dictionary
	BENCODE_TOK_DICT
};

typedef struct bencode_s bencode_t;

typedef struct
{
	/**
	@param dict_key: dictionary key for this item. This is set to null for list entries.
	@param val: integer value
	@return 0 on error; 1 otherise
	**/

	int (*hit_int)(bencode_t *s, const char *dict_key, const long int val);

	/**
	Call this when there is some string for us to read. This callback could fire multiple
	times for large strings.

	@param dict_key: the dictionary key for this item. this is set to null for list entries.
	@param v_total_len: total length of the string
	@param val: string value
	@param v_len: lenght of string we are currently emitting.
	@return 0 on error; 1 otherwise
	**/
	int (*hit_str)(
		bencode_t *s, 
		const char *dict_key, 
		unsigned int v_total_len, 
		const unsigned char *val, 
		unsigned int v_len);
}








































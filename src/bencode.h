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
	
	/**
	@param dict_key: Dictionary key for this item. This is set to null for list entries.
	@param val: Integer value
	@return 0 on error; 1 otherwise
	**/
	int (*dict_enter)(bencode_s *s, const char *dict_key);

	/**
	Called when we have finished processing a dictionary.
	
	@param dict_key: Dictionary key for this item. This is set to null for list entries.
	@paramt val: Integer value (TODO: not in params. Update github repo? This is same with other callbacks in this struct.)
	@return 0 on error; 1 otherwise
	**/
	int (*dict_leave)(bencode_t *s, const char *dict_key);

	/**
	@param dict_key: Dictionary key for this item. This is set to null for list entries.
	@param val: Integer value
	@return 0 on error; 1 otherwise.
	**/
	int (*list_enter)(bencode_t *s, const char *dict_key);

	/**
	@param dict_key: Dictionary key for this item. This is set to null for list entries.
	@param val: Integer value.
	@return 0 on error; 1 otherwise.
	**/
	int (*list_leave)(bencode_t *s, const char *dict_key);

	/**
	Called when we have just finished processing a list item.
	@return 0 on error; 1 otherwise.
	**/
	int (*list_next)(bencode_t *s);

	/**
	Called when we have just finished processing a dict item.
	@return 0 on error; 1 otherwise.
	**/
	int (*dict_next)(bencode_t *s);
} bencode_callbacks_t;


typedef struct
{
	// dictionary key
	char *key;
	int k_size;

	// string value
	char *strval;
	int sv_size;

	long int intval;
	
	int len;

	int pos;

	// token type
	int type;

	// user data for context specific to frame
	void *udata;
} bencode_frame_t;

struct bencode_s
{
	// stack
	bencode_frame_t *stk;

	// number of frames we can push down, i.e. maximum depth
	unsigned int nframes;

	// current depth within stack
	unsigned int d;

	// user data for context
	void *udata;

	bencode_callbacks_t cb;

}

/**
@param expected_depth: Expected depth pf bencode
@param cb: Callbacks we need to parse the bencode
@return new memory for bencode parser
**/
bencode_t *bencode_new(int expected_depth, bencode_callbacks_t *cb, void *udata);

/**
Initialise reader
**/
void bencode_init(bencode_t *);

/**
@param buf: Buffer to read new input from
@param len: size of the buffer
@return 0 on error; 1 otherwise
**/
int bencode_dispatch_from_buffer(bencode_t *, const char *buf, unsigned int len);


/**
@param cb: Callbacks we need to parse bencode.
**/
void bencode_set_callbacks(bencode_t *, bencode_callbacks_t *cb);

#endif

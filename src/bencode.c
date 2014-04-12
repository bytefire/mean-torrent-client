#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>
#include<ctype.h>
#include<math.h>

#include "bencode.h"

bencode_t *bencode_new(int expected_depth, bencode_callbacks_t *cb, void *udata)
{
	bencode_t *me;

	me = calloc(1, sizeof bencode_t); // calloc is like malloc but it also initialises memory to zero.
	bencode_set_callbacks(me, cb);
	me->udata = udata;
	me->nframes = expected_depth;
	me->stk = calloc(10 + expected_depth, sizeof bencode_frame_t);

	return me;
}

void bencode_init(bencode_t *me)
{
	memset(me, 0, sizeof bencode_t);
}

// pushes a new bencode_frame_t onto the stack in bencode_t and returns a pointer to it.
static bencode_frame_t *__push_stack(bencode_t *me)
{
	if(me->nframes <= me->d)
	{
		assert(0);
		return NULL;
	}

	me->d++;

	bencode_frame_t *s = &me->stk[me->d];

	s->pos = 0;
	s->intval = 0;
	s->len = 0;
	s->type = 0;

	if(s->sv_size == 0)
	{
		s->sv_size = 20; // TODO: what does 20 mean? is it arbitrary?
		s->strval = malloc(s->sv_size);
	}

	if(s->k_size == 0)
	{
		s->k_size = 20;
		s->key = malloc(s->k_size);
	}

	return &me->stk[me->d];
}

// calls corresponding leave methods on the bencode_frame_t that at the top of the stack,
// decrements the top of stack pointer and returns the frame next to top (which becomes top).
static bencode_frame_t *__pop_stack(bencode_t *me)
{
	bencode_frame_t *f;
	f = &me->stk[me->d];

	switch(f->type)
	{
		case BENCODE_TOK_LIST:
			if(me->cb.list_leave)
				me->cb.list_leave(me, f->key);
			break;
		case BENCODE_TOK_DICT:
			if(me->cb.dict_leave)
				me->cb.dict_leave(me, f->key);
			break;
	}

	if(me->d == 0)
	{
		return NULL;
	}

	f = &me->stk[--me->d];

	switch(f->type)
	{
		case BENCODE_TOK_LIST:
			if(me->cb.list_next)
			{
				me->cb.list_next(me);
			}
			break;

		case BENCODE_TOK_DICT:
			if(me->cb.dict_next)
			{
				me->cb.dict_next(me);
			}
			break;
	}

	return f;
}

// parses decimal number, one digit at a time
static int __parse_digit(const int current_value, const char c)
{
	return (c-'0') + current_value * 10;		
}

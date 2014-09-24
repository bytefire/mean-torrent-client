#ifndef SHA1_H
#define SHA1_H

#pragma once

#include<stdint.h>

// uses the method described here: https://tools.ietf.org/html/rfc3174#section-6.1 
void sha1_compute(uint8_t *msg, int msg_len, uint8_t *sha1);

#endif // SHA1_H

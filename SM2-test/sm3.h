#pragma once
/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM3_H
# define HEADER_SM3_H

# include "opensslconf.h"
# include <stddef.h>

# ifdef OPENSSL_NO_SM3
#  error SM3 is disabled.
# endif

# define SM3_DIGEST_LENGTH 32
# define SM3_WORD unsigned int

# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct SM3state_st {
		SM3_WORD A, B, C, D, E, F, G, H;
		SM3_WORD Nl, Nh;
		SM3_WORD data[SM3_LBLOCK];
		unsigned int num;
	} SM3_CTX;

	int sm3_init(SM3_CTX *c);
	//int sm3_update(SM3_CTX *c, const void *data, size_t len);
	//int sm3_final(unsigned char *md, SM3_CTX *c);
	int sm3_hash(unsigned char *msg, unsigned char *md, int len);

	void sm3_block_data_order(SM3_CTX *c, const void *p, size_t num);

#ifdef __cplusplus
} /* end of extern "C" */
#endif
#endif

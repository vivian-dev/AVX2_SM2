#pragma once
//±àÂë
#ifndef BER_h
#define BER_h
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char byte;
void Bytes_encode(byte* cypher, int length, byte** output);
void Bytes_decode(byte** cypher, int* length, byte* input);
void SM2_PublicKey_encode(byte X[], byte Y[], byte** output);
void SM2_PublicKey_decode(byte X[], byte Y[], byte* input);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* BER_h */
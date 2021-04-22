#ifndef SM2_H
#define SM2_H
#include<stdint.h>
#include<stdio.h>
#include"curve.h"
#include"common.h"

/*
给定私钥sk产生公钥pk
输入：无
输出：p_sk：私钥（256bit）
      p_ pk：公钥（512bit）
返回：1，密钥对成功生成
	  0，密钥对生成失败
*/
int sm2_make_key(uint8_t p_sk[SM2_BYTES], uint8_t p_pk_X[SM2_BYTES], uint8_t p_pk_Y[SM2_BYTES]);
int sm2_make_key_2w(uint8_t p_sk[SM2_BYTES], uint8_t p_pk_X[SM2_BYTES], uint8_t p_pk_Y[SM2_BYTES]);
/*
共享密钥计算
输入：p_pk,对方公钥（压缩形式x坐标）
	  p_sk，自己私钥
输出：p_ss，共享密钥（x坐标）
返回：1，共享密钥计算成功
	  0，出错
*/
int sm2_shared_secret(const uint8_t p_pk[SM2_BYTES + 1], const uint8_t p_sk[SM2_BYTES], uint8_t p_ss[SM2_BYTES]);
/*
加密函数
输入：p_pk_X,p_pk_Y  公钥
	  M，待加密消息 
	  mlen，消息长度
	
输出：cipher，SM2密文,长度比输入的明文长96字节，C1(64字节)C3(32字节)
返回：1，加密成功
	  0，加密失败
*/
int sm2_encrypt(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher);
int sm2_encrypt_2w(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher);
/*
解密函数
输入：sk，SM2私钥
	  cipher，SM2密文
	  klen，

输出：plain，明文
返回：1，解密成功
	  0，解密失败
*/
int sm2_decrypt(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain);
int sm2_decrypt_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain);
/*
给定消息生成签名
A3----A7
输入:p_sk，签名者私钥
	 p_hash，待签名消息hash值（预处理2结果）
输出：p_sign，签名值（64byte）
返回：0，失败
	  1，成功
*/
int sm2_sign(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2]);
int sm2_sign_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2]);
/*
验证签名
B1B2 B5B6B7
输入：  sign，签名值
		pk，签名者公钥
		p_hash，待验证消息hash值
输出：  1，验证通过
		0，验证不通过
*/
int sm2_verify(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_sign[SM2_BYTES * 2]);
int sm2_verify_2w(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_sign[SM2_BYTES * 2]);
/*
密钥派生函数
输入：Z,比特串
	  klen，要获得的密钥数据字节长度
返回：K，长为klen的密钥数据比特串K
*/
unsigned char* sm2_kdf(unsigned char Z[SM2_BYTES * 2], int klen);
void  print_sk(uint8_t p_sk[SM2_BYTES]);
void print_affpoint(uint8_t p_pk_X[SM2_BYTES],uint8_t p_pk_Y[SM2_BYTES]);
void print_sign(uint8_t p_sign[SM2_BYTES * 2]);
#endif

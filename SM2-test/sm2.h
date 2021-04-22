#ifndef SM2_H
#define SM2_H
#include<stdint.h>
#include<stdio.h>
#include"curve.h"
#include"common.h"

/*
����˽Կsk������Կpk
���룺��
�����p_sk��˽Կ��256bit��
      p_ pk����Կ��512bit��
���أ�1����Կ�Գɹ�����
	  0����Կ������ʧ��
*/
int sm2_make_key(uint8_t p_sk[SM2_BYTES], uint8_t p_pk_X[SM2_BYTES], uint8_t p_pk_Y[SM2_BYTES]);
int sm2_make_key_2w(uint8_t p_sk[SM2_BYTES], uint8_t p_pk_X[SM2_BYTES], uint8_t p_pk_Y[SM2_BYTES]);
/*
������Կ����
���룺p_pk,�Է���Կ��ѹ����ʽx���꣩
	  p_sk���Լ�˽Կ
�����p_ss��������Կ��x���꣩
���أ�1��������Կ����ɹ�
	  0������
*/
int sm2_shared_secret(const uint8_t p_pk[SM2_BYTES + 1], const uint8_t p_sk[SM2_BYTES], uint8_t p_ss[SM2_BYTES]);
/*
���ܺ���
���룺p_pk_X,p_pk_Y  ��Կ
	  M����������Ϣ 
	  mlen����Ϣ����
	
�����cipher��SM2����,���ȱ���������ĳ�96�ֽڣ�C1(64�ֽ�)C3(32�ֽ�)
���أ�1�����ܳɹ�
	  0������ʧ��
*/
int sm2_encrypt(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher);
int sm2_encrypt_2w(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher);
/*
���ܺ���
���룺sk��SM2˽Կ
	  cipher��SM2����
	  klen��

�����plain������
���أ�1�����ܳɹ�
	  0������ʧ��
*/
int sm2_decrypt(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain);
int sm2_decrypt_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain);
/*
������Ϣ����ǩ��
A3----A7
����:p_sk��ǩ����˽Կ
	 p_hash����ǩ����Ϣhashֵ��Ԥ����2�����
�����p_sign��ǩ��ֵ��64byte��
���أ�0��ʧ��
	  1���ɹ�
*/
int sm2_sign(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2]);
int sm2_sign_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2]);
/*
��֤ǩ��
B1B2 B5B6B7
���룺  sign��ǩ��ֵ
		pk��ǩ���߹�Կ
		p_hash������֤��Ϣhashֵ
�����  1����֤ͨ��
		0����֤��ͨ��
*/
int sm2_verify(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_sign[SM2_BYTES * 2]);
int sm2_verify_2w(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_sign[SM2_BYTES * 2]);
/*
��Կ��������
���룺Z,���ش�
	  klen��Ҫ��õ���Կ�����ֽڳ���
���أ�K����Ϊklen����Կ���ݱ��ش�K
*/
unsigned char* sm2_kdf(unsigned char Z[SM2_BYTES * 2], int klen);
void  print_sk(uint8_t p_sk[SM2_BYTES]);
void print_affpoint(uint8_t p_pk_X[SM2_BYTES],uint8_t p_pk_Y[SM2_BYTES]);
void print_sign(uint8_t p_sign[SM2_BYTES * 2]);
#endif

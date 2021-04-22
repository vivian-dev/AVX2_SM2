#pragma once
#ifndef PFD_H
#define PFD_H
#include<stdint.h>
#include"limb.h"
#include"common.h"


#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
#define SUPPORTS_INT128 1
#else
#define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
	uint64_t m_low;
	uint64_t m_high;
} uint128_t;
#endif
//��·
int bytes_is_zero(const uint8_t *input, int len);
/*unsigned int���������Ƚϴ�С*/
unsigned int umax(unsigned int a, unsigned int b);
/*�������Ƿ�Ϊ0
���룺p_bn
���أ�0��p_bn==0
	  1��p_bn!=0
*/
 int bn_isZero(uint64_t *p_bn);
/*��ʼ������Ϊ0
*/
 void bn_init0(uint64_t *p_bn);
/*��������ֵ����
���룺p_src,p_dest
�����p_dest<-p_src
*/
 void bn_set(uint64_t *p_dest, uint64_t *p_src);
/*����������1bit����
���룺p_bn
�����p_bn=p_bn>>1*/
 void bn_rshift1(uint64_t *p_bn);
/*�������Ʋ���
���룺p_in,p_shift
�����p_result=p_in<<p_shitf*/
 uint64_t bn_lshift(uint64_t *p_result, uint64_t *p_in, unsigned int p_shift);
/*����bitλ��
���룺p_bn,p_bit
���أ�1��p_bn��p_bitλ��Ϊ1
	  0������
*/
 uint64_t bn_testBit(uint64_t *p_bn, int p_bit);
 //����64bit���������Ʊ�ʾ��bit����
 unsigned int numBits(uint64_t num);
/*���������Ʊ�ʾ��bit����
���룺p_bn
���أ�p_bn��bit����*/
 unsigned int bn_numBits(uint64_t *p_bn);
 unsigned int bn_numDigits(uint64_t *p_bn);
/*�������ӷ�(NUM_DIGITS_SM2->NUM_DIGITS_SM2)
���룺p_left,p_right
�����p_result=p_left+p_right 
*/
 uint64_t bn_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*����������
���룺p_left,p_right
�����p_result=p_left-p_right
���أ���λ
*/
 uint64_t bn_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*������ƽ����
*/
 void mod_sqrt(uint64_t a[NUM_DIGITS_SM2]);
/*�������Ƚ�
���룺p_left,p_right
���أ�1��p_left>p_right
	  -1,p_left<p_right
	  0.p_left=p_right
*/
 int bn_cmp(uint64_t *p_left, uint64_t *p_right);
/*������ģ��
���룺p_left,p_right,p_mod
�����p_result=(p_left+p_right)%p_mod
*/
 void bn_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*������ģ��
���룺p_left,p_right,p_mod
�����p_result=(p_left-p_right)%p_mod
*/
 void bn_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*����������Լ��*/
 void bn_mmod_fast(uint64_t *p_result, uint64_t *p_product);
/*����������ģ��
����bn_mul,bn_mmod_fast
���룺p_left,p_right
�����p_result=p_left*p_right%curve_p
*/
 void bn_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*����������ģƽ��
����bn_square,bn_mmod_fast
���룺p_left
�����p_result=p_left^2%curve_p
*/
 void bn_modSquare_fast(uint64_t *p_result, uint64_t *p_left);
/*������ģ��
*/
 void bn_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*������ģ��
ԭ��https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
���룺p_input��p_mod
�����p_result=(1/p_input)%p_mod
*/
 void bn_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod);
 /*
 ������ģ�棬ʹ�üӷ���
 ԭ��https://doi.org/10.1145/3236010
 ���룺p_input��p_mod
 �����p_result=(1/p_input)%p_mod
 */
 void bn_modinv_addchain(uint64_t *p_result, uint64_t *p_input);
#if SUPPORTS_INT128   //ֱ��ʹ��uint128���г˷����㣨64*64->128��
 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
#else 
/*64bit�����˷�(64*64->128bit)
���룺p_left,p_right(64bit)
���أ�p_left*p_right(128bit)
*/
 uint128_t mul_64_64(uint64_t p_left, uint64_t p_right);
/*128bit�����ӷ�(128+128->128bit)
���룺a��b
���أ�a+b
*/
 uint128_t add_128_128(uint128_t a,uint128_t b);
/*�������˷�(NUM__DIGITS_SM2*NUM__DIGITS_SM2->2NUM__DIGITS_SM2)
���룺p_left,p_right(NUM__DIGITS_SM2)
�����p_result=p_left*p_right(2NUM__DIGITS_SM2)
*/
 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*������ƽ��(NUM__DIGITS_SM2*NUM__DIGITS_SM2->2NUM__DIGITS_SM2)
���룺p_left
�����p_result=p_left^2(2NUM__DIGITS_SM2)
*/
 void bn_square(uint64_t *p_result, uint64_t *p_left);
#endif

 //����ʵ��
 /*fullradix��radix-26����ת��*/
 void radix64to26(uint64_t v[NLIMB], uint64_t a[NUM_DIGITS_SM2]);
 /*���鵽������ӳ��*/
 void set_vector(vec z[NLIMB / 2], const uint64_t x[NLIMB], const uint64_t y[NLIMB]);
 /*�������鵽������ӳ��*/
 void set_prime(vec z[NLIMB / 2], const uint64_t x[NLIMB]);
 /*����Ԫ�ص�����Ԫ�ص�ӳ��*/
 void vecto64(uint64_t x[NUM_DIGITS_SM2], uint64_t y[NUM_DIGITS_SM2], vec z[NLIMB / 2]);
 /*����õ���Ӧͨ����Ԫ��*/
 void get_channel(uint64_t r[NLIMB], const vec z[NLIMB / 2], const int ch0, const int ch1);
 /*���Է�֧����*/
 int test_limbsign(vec *r);
 /*
 ��·����
 ���룺x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 �����r[NLIMB/2]=<E,F>
       E=A-C  ,F=B-D
 */
 void vec_2w_sub(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 ��·�ӷ�
 ���룺x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 �����r[NLIMB/2]=<E,F>
	   E=A+C  ,F=B+D
 */
 void vec_2w_add(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 ��·ģƽ��
 ���룺x=<A,B>
 �����r=<E,F>
		E=A^2modp  ,F=B^2modp
 */
 void vec_2w_modsqr(vec r[NLIMB / 2], const vec x[NLIMB / 2]);
 /*
 ��·ģ��
 ���룺x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 �����r[NLIMB/2]=<E,F>
		E=A*Cmodp  ,F=B*Dmodp
 r=xy
 */
 void vec_2w_modmul(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 2·����Լ���㷨
 ���룺Z[NLIMB]������20��limbs�������Ϊ60bit
 �����r[NLIMB/2],����10��limb�������Ϊ28bit
 */
 void vec_2w_fastred(vec r[NLIMB/2],vec Z[NLIMB]);
 /*
 in place carry
 ���룺r[NLIMB/2],�����Ϊ60bit��10��limb
 �����r[NLIMB/2],�����Ϊ28bit��10��limb
 */
 void vec_2w_carry(vec r[NLIMB / 2]);


#endif
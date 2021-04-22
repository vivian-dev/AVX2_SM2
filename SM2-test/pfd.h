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
//单路
int bytes_is_zero(const uint8_t *input, int len);
/*unsigned int两个整数比较大小*/
unsigned int umax(unsigned int a, unsigned int b);
/*大整数是否为0
输入：p_bn
返回：0，p_bn==0
	  1，p_bn!=0
*/
 int bn_isZero(uint64_t *p_bn);
/*初始化大数为0
*/
 void bn_init0(uint64_t *p_bn);
/*大整数赋值操作
输入：p_src,p_dest
输出：p_dest<-p_src
*/
 void bn_set(uint64_t *p_dest, uint64_t *p_src);
/*大整数右移1bit操作
输入：p_bn
输出：p_bn=p_bn>>1*/
 void bn_rshift1(uint64_t *p_bn);
/*大数左移操作
输入：p_in,p_shift
输出：p_result=p_in<<p_shitf*/
 uint64_t bn_lshift(uint64_t *p_result, uint64_t *p_in, unsigned int p_shift);
/*大数bit位置
输入：p_bn,p_bit
返回：1，p_bn在p_bit位置为1
	  0，否则
*/
 uint64_t bn_testBit(uint64_t *p_bn, int p_bit);
 //测试64bit整数二进制表示的bit长度
 unsigned int numBits(uint64_t num);
/*大数二进制表示的bit长度
输入：p_bn
返回：p_bn的bit长度*/
 unsigned int bn_numBits(uint64_t *p_bn);
 unsigned int bn_numDigits(uint64_t *p_bn);
/*大整数加法(NUM_DIGITS_SM2->NUM_DIGITS_SM2)
输入：p_left,p_right
输出：p_result=p_left+p_right 
*/
 uint64_t bn_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*大整数减法
输入：p_left,p_right
输出：p_result=p_left-p_right
返回：借位
*/
 uint64_t bn_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*大整数平方根
*/
 void mod_sqrt(uint64_t a[NUM_DIGITS_SM2]);
/*大整数比较
输入：p_left,p_right
返回：1，p_left>p_right
	  -1,p_left<p_right
	  0.p_left=p_right
*/
 int bn_cmp(uint64_t *p_left, uint64_t *p_right);
/*大整数模加
输入：p_left,p_right,p_mod
输出：p_result=(p_left+p_right)%p_mod
*/
 void bn_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*大整数模减
输入：p_left,p_right,p_mod
输出：p_result=(p_left-p_right)%p_mod
*/
 void bn_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*大整数快速约减*/
 void bn_mmod_fast(uint64_t *p_result, uint64_t *p_product);
/*大整数快速模乘
调用bn_mul,bn_mmod_fast
输入：p_left,p_right
输出：p_result=p_left*p_right%curve_p
*/
 void bn_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*大整数快速模平方
调用bn_square,bn_mmod_fast
输入：p_left
输出：p_result=p_left^2%curve_p
*/
 void bn_modSquare_fast(uint64_t *p_result, uint64_t *p_left);
/*大整数模乘
*/
 void bn_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
/*大整数模逆
原理：https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
输入：p_input，p_mod
输出：p_result=(1/p_input)%p_mod
*/
 void bn_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod);
 /*
 大整数模逆，使用加法链
 原理：https://doi.org/10.1145/3236010
 输入：p_input，p_mod
 输出：p_result=(1/p_input)%p_mod
 */
 void bn_modinv_addchain(uint64_t *p_result, uint64_t *p_input);
#if SUPPORTS_INT128   //直接使用uint128进行乘法运算（64*64->128）
 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
#else 
/*64bit整数乘法(64*64->128bit)
输入：p_left,p_right(64bit)
返回：p_left*p_right(128bit)
*/
 uint128_t mul_64_64(uint64_t p_left, uint64_t p_right);
/*128bit整数加法(128+128->128bit)
输入：a，b
返回：a+b
*/
 uint128_t add_128_128(uint128_t a,uint128_t b);
/*大整数乘法(NUM__DIGITS_SM2*NUM__DIGITS_SM2->2NUM__DIGITS_SM2)
输入：p_left,p_right(NUM__DIGITS_SM2)
输出：p_result=p_left*p_right(2NUM__DIGITS_SM2)
*/
 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right);
/*大整数平方(NUM__DIGITS_SM2*NUM__DIGITS_SM2->2NUM__DIGITS_SM2)
输入：p_left
输出：p_result=p_left^2(2NUM__DIGITS_SM2)
*/
 void bn_square(uint64_t *p_result, uint64_t *p_left);
#endif

 //并行实现
 /*fullradix到radix-26数组转换*/
 void radix64to26(uint64_t v[NLIMB], uint64_t a[NUM_DIGITS_SM2]);
 /*数组到向量的映射*/
 void set_vector(vec z[NLIMB / 2], const uint64_t x[NLIMB], const uint64_t y[NLIMB]);
 /*素数数组到向量的映射*/
 void set_prime(vec z[NLIMB / 2], const uint64_t x[NLIMB]);
 /*向量元素到素域元素的映射*/
 void vecto64(uint64_t x[NUM_DIGITS_SM2], uint64_t y[NUM_DIGITS_SM2], vec z[NLIMB / 2]);
 /*分离得到对应通道的元素*/
 void get_channel(uint64_t r[NLIMB], const vec z[NLIMB / 2], const int ch0, const int ch1);
 /*测试分支符号*/
 int test_limbsign(vec *r);
 /*
 二路减法
 输入：x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 输出：r[NLIMB/2]=<E,F>
       E=A-C  ,F=B-D
 */
 void vec_2w_sub(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 二路加法
 输入：x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 输出：r[NLIMB/2]=<E,F>
	   E=A+C  ,F=B+D
 */
 void vec_2w_add(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 二路模平方
 输入：x=<A,B>
 输出：r=<E,F>
		E=A^2modp  ,F=B^2modp
 */
 void vec_2w_modsqr(vec r[NLIMB / 2], const vec x[NLIMB / 2]);
 /*
 二路模乘
 输入：x[NLIMB/2]=<A,B>
	   y[NLIMB/2]=<C,D>
 输出：r[NLIMB/2]=<E,F>
		E=A*Cmodp  ,F=B*Dmodp
 r=xy
 */
 void vec_2w_modmul(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2]);
 /*
 2路快速约减算法
 输入：Z[NLIMB]，包含20个limbs，最长长度为60bit
 输出：r[NLIMB/2],包含10个limb，最长长度为28bit
 */
 void vec_2w_fastred(vec r[NLIMB/2],vec Z[NLIMB]);
 /*
 in place carry
 输入：r[NLIMB/2],最长长度为60bit的10个limb
 输出：r[NLIMB/2],最长长度为28bit的10个limb
 */
 void vec_2w_carry(vec r[NLIMB / 2]);


#endif
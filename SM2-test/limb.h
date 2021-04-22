#ifndef LIMB_H
#define LIMB_H
//AVX����ָ�������
#include<immintrin.h>
//SM2�������ߣ����򳤶�Ϊ256bit
#define NLIMB 10  //  ��256/radix��
#define BITSSM2 26      //radixΪ26
typedef __m256i vec;
#ifndef ALIGN
#define ALIGN __attribute__((aligned(32)))
#endif

//��������
#define VADD(X,Y)          _mm256_add_epi64(X,Y)   //256bit����X,Y�ֱ�64bit���
#define VSUB(X,Y)		   _mm256_sub_epi64(X, Y) 
#define VMUL(X, Y)         _mm256_mul_epu32(X, Y)
//#define VMAC(Z, X, Y)      VADD(Z, VMUL(X, Y))
//#define VABS8(X)           _mm256_abs_epi8(X)
// �߼�����
//#define VXOR(X, Y)         _mm256_xor_si256(X, Y)
#define VAND(X, Y)         _mm256_and_si256(X, Y)
//#define VOR(X, Y)          _mm256_or_si256(X, Y)
#define VSHR(X, Y)         _mm256_srli_epi64(X, Y)
#define VSHRV(X, Y)        _mm256_srlv_epi64(X,Y)
#define VSHL(X, Y)         _mm256_slli_epi64(X, Y)
#define VSHLV(X, Y)        _mm256_sllv_epi64(X,Y)
#define BLEND32(X, Y, Z)   _mm256_blend_epi32(X,Y,Z)
#define ALIGNR(X, Y)       _mm256_castpd_si256(_mm256_shuffle_pd(_mm256_castsi256_pd(Y),_mm256_castsi256_pd(X),0x5))
// �ڴ���ʺ͹㲥
//#define VLOAD128(X)        _mm_load_si128((__m128i*)X)
#define VSET164(X)         _mm256_set1_epi64x(X)  //64bitlongԪ��X�㲥��256bit����
#define VSET64(W, X, Y, Z) _mm256_set_epi64x(W, X, Y, Z)
#define VZERO              _mm256_setzero_si256()
//#define VEXTR32(X, Y)      _mm256_extract_epi32(X, Y)
#define SHUFPD(X, Y, Z)    _mm256_castpd_si256(_mm256_shuffle_pd(_mm256_castsi256_pd(X),_mm256_castsi256_pd(Y),Z))
#define VPERM64(X, Y)      _mm256_permute4x64_epi64(X, Y)
#define VPERM128(X,Y,Z)    _mm256_permute2x128_si256(X,Y,Z)
//#define ALIGNR(X,Y)  SHUFPD(X,Y,0x05)

#endif

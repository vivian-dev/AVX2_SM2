#ifndef CURVE_H
#define CURVE_H
#include"pfd.h"
#include"common.h"
/*�����Ƿ���������*/
int ECC_check_point(affpoint *p_point);
/*��ѹ��
���룺p_compress[],ѹ����ʽ��������
�����p_point������������ʽ����
*/
 void ecc_point_decompress(affpoint *p_point, const uint8_t p_compressed[SM2_BYTES + 1]);
/*radixת��Ϊ64bit*/
 void ecc_bytes2native(uint64_t p_native[NUM_DIGITS_SM2], const uint8_t p_bytes[SM2_BYTES]);
/*radixת��Ϊ8bit*/
 void ecc_native2bytes(uint8_t p_bytes[SM2_BYTES], const uint64_t p_native[NUM_DIGITS_SM2]);
 int EccPoint_isZero(affpoint *p_point);
/*��������ת��ΪXYCZ-Jacobian����
���룺(X1,Y1),��������
	  Z,����ת���Ĺ����Z����
�����(X1*Z^2,Y1*Z^3),XYCZ-Jacobian����
*/
 void AFF2XYCZ(uint64_t *X1, uint64_t *Y1, uint64_t *Z);
/*Jacobian�����µı���
ԭ��Jacobian���걶�㹫ʽ���ı�z����
���룺P=(X1,Y1,Z1)  Jacobian����
�����2P=(X1,Y1,Z1)  Jacobian����
*/
 void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1);
/*��ʼ��������
ԭ��http://eprint.iacr.org/2011/338.pdf ���ı�z����
���룺(X1,Y1),(X2,Y2)  ��������
	  Z   ����ת����z����
�����2P=(X1,Y1,Z) 
	  P�������=(X2,Y2,Z)   XYCZ-Jacobian����
*/
 void XYCZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ);
/*
radix64�������
���룺P=(X1,Y1)
	  Q=(X2,Y2)   XYCZ-Jacobian�����XY����
�����P+Q=(X2,Y2)
	  P�������=(X1,Y1)  XYCZ-Jacobian�����XY����
	  Z(P)=Z(P+Q)
*/
 void XYCZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2);
 /*
 in place 2·���
 ���룺P=<X1,Y1>
	   Q=<X2,Y2>   XYCZ-Jacobian�����XY����
 �����P+Q=<X2,Y2>
	   P�������=<X1,Y1>  XYCZ-Jacobian�����XY����
	   Z(P)=Z(P+Q)
 */
 void XYCZ_2w_add(vec X1Y1[NLIMB/2], vec X2Y2[NLIMB/2]);
/*
radix64����������
���룺P=(X1,Y1)
	  Q=(X2,Y2)   XYCZ-Jacobian�����XY����
�����P+Q=(X2,Y2)
	  P-Q=(X1,Y1)  XYCZ-Jacobian�����XY����
	  Z(P+Q)=Z(P-Q)
*/
 void XYCZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2);
 /*
 in place 2·������  
 ���룺P=<X1,Y1>
	   Q=<X2,Y2>   XYCZ-Jacobian�����XY����
 �����P+Q=<X2,Y2>
	   P-Q=<X1,Y1>  XYCZ-Jacobian�����XY����
	   Z(P+Q)=Z(P-Q)
 */
 void XYCZ_2w_addC(vec X1Y1[NLIMB / 2], vec X2Y2[NLIMB / 2], vec AT[NLIMB / 2]);
/*
radix64����������
ԭ��XYCO-Montgomery ladder�㷨
���룺p_point,p_scalar,p_initialZ
�����p_result=p_scalar*p_point(�����)
*/
 void EccPoint_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ);
 /*
2·����������
ԭ��XYCO-Montgomery ladder�㷨
���룺p_point,p_scalar,p_initialZ
�����p_result=p_scalar*p_point(�����)
*/
 void EccPoint_2w_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ);

#endif

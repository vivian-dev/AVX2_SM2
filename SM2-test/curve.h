#ifndef CURVE_H
#define CURVE_H
#include"pfd.h"
#include"common.h"
/*检测点是否在曲线上*/
int ECC_check_point(affpoint *p_point);
/*解压缩
输入：p_compress[],压缩形式仿射坐标
输出：p_point，完整仿射形式坐标
*/
 void ecc_point_decompress(affpoint *p_point, const uint8_t p_compressed[SM2_BYTES + 1]);
/*radix转换为64bit*/
 void ecc_bytes2native(uint64_t p_native[NUM_DIGITS_SM2], const uint8_t p_bytes[SM2_BYTES]);
/*radix转换为8bit*/
 void ecc_native2bytes(uint8_t p_bytes[SM2_BYTES], const uint64_t p_native[NUM_DIGITS_SM2]);
 int EccPoint_isZero(affpoint *p_point);
/*仿射坐标转换为XYCZ-Jacobian坐标
输入：(X1,Y1),仿射坐标
	  Z,用于转换的共享的Z坐标
输出：(X1*Z^2,Y1*Z^3),XYCZ-Jacobian坐标
*/
 void AFF2XYCZ(uint64_t *X1, uint64_t *Y1, uint64_t *Z);
/*Jacobian坐标下的倍点
原理：Jacobian坐标倍点公式，改变z坐标
输入：P=(X1,Y1,Z1)  Jacobian坐标
输出：2P=(X1,Y1,Z1)  Jacobian坐标
*/
 void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1);
/*初始倍点运算
原理：http://eprint.iacr.org/2011/338.pdf ，改变z坐标
输入：(X1,Y1),(X2,Y2)  仿射坐标
	  Z   用来转换的z坐标
输出：2P=(X1,Y1,Z) 
	  P坐标更新=(X2,Y2,Z)   XYCZ-Jacobian坐标
*/
 void XYCZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ);
/*
radix64点加运算
输入：P=(X1,Y1)
	  Q=(X2,Y2)   XYCZ-Jacobian坐标的XY坐标
输出：P+Q=(X2,Y2)
	  P坐标更新=(X1,Y1)  XYCZ-Jacobian坐标的XY坐标
	  Z(P)=Z(P+Q)
*/
 void XYCZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2);
 /*
 in place 2路点加
 输入：P=<X1,Y1>
	   Q=<X2,Y2>   XYCZ-Jacobian坐标的XY坐标
 输出：P+Q=<X2,Y2>
	   P坐标更新=<X1,Y1>  XYCZ-Jacobian坐标的XY坐标
	   Z(P)=Z(P+Q)
 */
 void XYCZ_2w_add(vec X1Y1[NLIMB/2], vec X2Y2[NLIMB/2]);
/*
radix64共轭点加运算
输入：P=(X1,Y1)
	  Q=(X2,Y2)   XYCZ-Jacobian坐标的XY坐标
输出：P+Q=(X2,Y2)
	  P-Q=(X1,Y1)  XYCZ-Jacobian坐标的XY坐标
	  Z(P+Q)=Z(P-Q)
*/
 void XYCZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2);
 /*
 in place 2路共轭点加  
 输入：P=<X1,Y1>
	   Q=<X2,Y2>   XYCZ-Jacobian坐标的XY坐标
 输出：P+Q=<X2,Y2>
	   P-Q=<X1,Y1>  XYCZ-Jacobian坐标的XY坐标
	   Z(P+Q)=Z(P-Q)
 */
 void XYCZ_2w_addC(vec X1Y1[NLIMB / 2], vec X2Y2[NLIMB / 2], vec AT[NLIMB / 2]);
/*
radix64标量乘运算
原理：XYCO-Montgomery ladder算法
输入：p_point,p_scalar,p_initialZ
输出：p_result=p_scalar*p_point(仿射点)
*/
 void EccPoint_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ);
 /*
2路标量乘运算
原理：XYCO-Montgomery ladder算法
输入：p_point,p_scalar,p_initialZ
输出：p_result=p_scalar*p_point(仿射点)
*/
 void EccPoint_2w_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ);

#endif

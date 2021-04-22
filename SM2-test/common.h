#ifndef COMMON_H
#define COMMON_H

#define SM3_DIGEST_LENGTH 32
#define FAST_MODE 1
#define NUM_DIGITS_SM2 4
#define SM2_BYTES 32
#define MASK26 0x3FFFFFFUL
#define MASK52 0xFFFFFFFFFFFFFUL

//Jaocbian射影坐标点
typedef struct projective_point
{
	uint64_t x[NUM_DIGITS_SM2];
	uint64_t y[NUM_DIGITS_SM2];
	uint64_t z[NUM_DIGITS_SM2];
}ProPoint;
typedef ProPoint propoint;
//仿射坐标
typedef struct affine_point
{
	uint64_t x[NUM_DIGITS_SM2];
	uint64_t y[NUM_DIGITS_SM2];
}AffPoint;
typedef AffPoint affpoint;

//初始化sm2参数,外部变量的定义
uint64_t curve_p[NUM_DIGITS_SM2];
uint64_t curve_b[NUM_DIGITS_SM2];
uint64_t curve_a[NUM_DIGITS_SM2];
affpoint curve_G;
uint64_t curve_n[NUM_DIGITS_SM2];
#endif
#include"curve.h"
extern uint64_t curve_p[NUM_DIGITS_SM2];
extern uint64_t curve_b[NUM_DIGITS_SM2];
extern uint64_t curve_a[NUM_DIGITS_SM2];
extern affpoint curve_G;
extern uint64_t curve_n[NUM_DIGITS_SM2];
#define DEBUG 1
int ECC_check_point(affpoint *p_point)
{
	uint64_t temp[NUM_DIGITS_SM2];
	uint64_t y_square[NUM_DIGITS_SM2];

	bn_modSquare_fast(temp, p_point->x); /* temp = x^2 */
	bn_modAdd(temp, temp, curve_a, curve_p); /* temp = x^2 + a */
	bn_modMult_fast(temp, temp, p_point->x); /* temp = x^3 + ax */
	bn_modAdd(temp, temp, curve_b, curve_p); /* temp = x^3 + ax + b */
	bn_modSquare_fast(y_square, p_point->y);                       /*temp = sqrt(x^3 + ax + b) */

	if (bn_cmp(temp, y_square) == 0)    /* check if temp = y^2 */
		return 1;
	else
		return 0;
}
 void ecc_bytes2native(uint64_t p_native[NUM_DIGITS_SM2], const uint8_t p_bytes[SM2_BYTES])
{
	unsigned i;
	for (i = 0; i < NUM_DIGITS_SM2; ++i)
	{
		const uint8_t *p_digit = p_bytes + 8 * (NUM_DIGITS_SM2 - 1 - i);
		p_native[i] = ((uint64_t)p_digit[0] << 56) | ((uint64_t)p_digit[1] << 48) | ((uint64_t)p_digit[2] << 40) | ((uint64_t)p_digit[3] << 32) |
			((uint64_t)p_digit[4] << 24) | ((uint64_t)p_digit[5] << 16) | ((uint64_t)p_digit[6] << 8) | (uint64_t)p_digit[7];
	}
}
 void ecc_point_decompress(affpoint *p_point, const uint8_t p_compressed[SM2_BYTES + 1])
{
	ecc_bytes2native(p_point->x, p_compressed + 1);

	bn_modSquare_fast(p_point->y, p_point->x); /* y = x^2 */
	bn_modAdd(p_point->y, p_point->y, curve_a, curve_p); /* y = x^2 + a */
	bn_modMult_fast(p_point->y, p_point->y, p_point->x); /* y = x^3 + ax */
	bn_modAdd(p_point->y, p_point->y, curve_b, curve_p); /* y = x^3 + ax + b */

	mod_sqrt(p_point->y);

	if ((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
	{
		bn_sub(p_point->y, curve_p, p_point->y);
	}
}
 void ecc_native2bytes(uint8_t p_bytes[SM2_BYTES], const uint64_t p_native[NUM_DIGITS_SM2])
{
	unsigned i;
	for (i = 0; i < NUM_DIGITS_SM2; ++i)
	{
		uint8_t *p_digit = p_bytes + 8 * (NUM_DIGITS_SM2 - 1 - i);
		p_digit[0] = p_native[i] >> 56;
		p_digit[1] = p_native[i] >> 48;
		p_digit[2] = p_native[i] >> 40;
		p_digit[3] = p_native[i] >> 32;
		p_digit[4] = p_native[i] >> 24;
		p_digit[5] = p_native[i] >> 16;
		p_digit[6] = p_native[i] >> 8;
		p_digit[7] = p_native[i];
	}
}
 int EccPoint_isZero(affpoint *p_point)
{
	return (bn_isZero(p_point->x) && bn_isZero(p_point->y));
}
 void AFF2XYCZ(uint64_t *X1, uint64_t *Y1, uint64_t *Z)
{
	uint64_t t1[NUM_DIGITS_SM2];

	bn_modSquare_fast(t1, Z);    /* z^2 */
	bn_modMult_fast(X1, X1, t1); /* x1 * z^2 */
	bn_modMult_fast(t1, t1, Z);  /* z^3 */
	bn_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}
 void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1)
{
	/* t1 = X, t2 = Y, t3 = Z */
	uint64_t t4[NUM_DIGITS_SM2];
	uint64_t t5[NUM_DIGITS_SM2];
	if (bn_isZero(Z1))
	{
		return;
	}
	bn_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
	bn_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
	bn_modSquare_fast(t4, t4);   /* t4 = y1^4 */
	bn_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
	bn_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

	bn_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
	bn_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
	bn_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
	bn_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

	bn_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
	bn_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
	if (bn_testBit(X1, 0))
	{
		uint64_t l_carry = bn_add(X1, X1, curve_p);
		bn_rshift1(X1);
		X1[NUM_DIGITS_SM2 - 1] |= l_carry << 63;
	}
	else
	{
		bn_rshift1(X1);
	}
	/* t1 = 3/2*(x1^2 - z1^4) = B */
	bn_modSquare_fast(Z1, X1);      /* t3 = B^2 */
	bn_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
	bn_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
	bn_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
	bn_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
	bn_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

	bn_set(X1, Z1);
	bn_set(Z1, Y1);
	bn_set(Y1, t4);
}
 void XYCZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ)
{
	uint64_t z[NUM_DIGITS_SM2];

	bn_set(X2, X1);
	bn_set(Y2, Y1);

	bn_init0(z);
	z[0] = 1;
	if (p_initialZ)
	{
		bn_set(z, p_initialZ);
	}
	//（X1,Y1）转换为XYCZ-Jacobian坐标
	AFF2XYCZ(X1, Y1, z);
	EccPoint_double_jacobian(X1, Y1, z);
	//更新
	AFF2XYCZ(X2, Y2, z);
}
 void XYCZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
 {
	 /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	 uint64_t t5[NUM_DIGITS_SM2];

	 bn_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
	 bn_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
	 bn_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
	 bn_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
	 bn_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
	 bn_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */

	 bn_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
	 bn_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
	 bn_modSub(X2, X2, X1, curve_p); /* t3 = C - B */
	 bn_modMult_fast(Y1, Y1, X2);    /* t2 = y1*(C - B) */
	 bn_modSub(X2, X1, t5, curve_p); /* t3 = B - x3 */
	 bn_modMult_fast(Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
	 bn_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

	 bn_set(X2, t5);
 }
 void XYCZ_2w_add(vec X1Y1[NLIMB / 2], vec X2Y2[NLIMB / 2])
 {
	 int i = 0;
	 uint64_t tmp1[NUM_DIGITS_SM2], tmp2[NUM_DIGITS_SM2];
	 uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB], v_zero[NLIMB] = { 0 };

	 //<T1,T2)=<X2,Y2>-<X1,Y1>
	 vec T1T2[NLIMB / 2] = { VZERO };
	 vec_2w_sub(T1T2, X2Y2, X1Y1);
	 vecto64(tmp1, tmp2, T1T2);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(T1T2, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\nADD\n");
		 printf("T1=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T2=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<A,D>=<T1,T2>^2，需要约减
	 vec AD[NLIMB / 2] = { VZERO };
	 vec_2w_modsqr(AD, T1T2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, AD);
		 printf("A=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("D=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<B,C>=<X1,X2>*<A,A>
	 vec X1X2[NLIMB / 2], AA[NLIMB / 2], BC[NLIMB / 2] = { VZERO }, DA[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 X1X2[i] = VPERM128(X2Y2[i], X1Y1[i], 0X31);//x1y1和x2y2分离出x1x2
		 DA[i] = VPERM64(AD[i], 0X4E); //之后用到
		 AA[i] = BLEND32(DA[i], AD[i], 0XF0); //AD中分离出<A,A>
	 }
	 vec_2w_modmul(BC, X1X2, AA);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, BC);
		 printf("B=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("C=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<T1,0>=<B,0>+<C,0>
	 vec T10[NLIMB / 2] = { VZERO }, B0[NLIMB / 2], C0[NLIMB / 2], CB[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 B0[i] = BLEND32(VZERO, BC[i], 0XF0);
		 CB[i] = VPERM64(BC[i], 0X4E);//后面用到
		 C0[i] = BLEND32(VZERO, CB[i], 0XF0);
	 }
	 vec_2w_add(T10, B0, C0);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, T10);
		 printf("T1=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
	 }
	 */

	 //<X3,T3>=<D,C>-<T1,B>
	 vec X3T3[NLIMB / 2] = { VZERO }, DC[NLIMB / 2], T1B[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 DC[i] = BLEND32(BC[i], DA[i], 0xF0);
		 T1B[i] = BLEND32(CB[i], T10[i], 0XF0);
	 }
	 vec_2w_sub(X3T3, DC, T1B);
	 vecto64(tmp1, tmp2, X3T3);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(X3T3, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("X3=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T3=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<T1,0>=<B,0>-<X3,0>
	 vec X30[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 X30[i] = BLEND32(VZERO, X3T3[i], 0XF0);
	 }
	 vec_2w_sub(T10, B0, X30);
	 vecto64(tmp1, tmp2, T10);
	 radix64to26(v_tmp1, tmp1);
	 set_vector(T10, v_tmp1, v_zero);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("T1=B-X3:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 vecto64(tmp1, tmp2, B0);
		 printf("B=\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 vecto64(tmp1, tmp2, X30);
		 printf("X3=\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
	 }
	 */
	 //<T1,E>=<T1,Y1>*<T2,T3>
	 vec T1E[NLIMB / 2] = { VZERO }, T1Y1[NLIMB / 2], T2T3[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离出<T1,Y1><T2,T3>
		 T1Y1[i] = BLEND32(X1Y1[i], T10[i], 0XF0);
		 T2T3[i] = VPERM128(X3T3[i], T1T2[i], 0X20);
		 //T2T3[i] = BLEND32(VPERM64(T1T2[i], 0X0E), X3T3[i], 0XF0);
	 }
	 vec_2w_modmul(T1E, T1Y1, T2T3);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, T1E);
		 printf("T1=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("E=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<Y3,0>=<T1,0>-<E,0>
	 vec Y30[NLIMB / 2] = { VZERO }, E0[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离出<T1,0><E,0>
		 T10[i] = BLEND32(VZERO, T1E[i], 0XF0);
		 E0[i] = VPERM128(VZERO, T1E[i], 0X20);
	 }
	 vec_2w_sub(Y30, T10, E0);
	 vecto64(tmp1, tmp2, Y30);
	 radix64to26(v_tmp1, tmp1);
	 set_vector(Y30, v_tmp1, v_zero);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("Y3=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
	 }
	 */
	 //最终结果  in place
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 X1Y1[i] = BLEND32(T1E[i], B0[i], 0XF0);  //<X1,Y1>=<B,E>=P'
		 X2Y2[i] = VPERM128(Y30[i], X30[i], 0X31);//<X2,Y2>=<X3,Y3>=P+Q
	 }
	 /*
	 if (DEBUG)
	 {
		 vecto64(tmp1, tmp2, X1Y1);
		 printf("\n");
		 printf("<X1,Y1>=<B,E>:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
		 vecto64(tmp1, tmp2, X2Y2);
		 printf("<X2,Y2>=<X3,Y3>:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
 }
 void XYCZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	uint64_t t5[NUM_DIGITS_SM2];
	uint64_t t6[NUM_DIGITS_SM2];
	uint64_t t7[NUM_DIGITS_SM2];

	bn_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
	bn_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
	bn_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
	bn_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
	bn_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
	bn_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

	bn_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
	bn_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
	bn_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
	bn_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 */
	bn_modSub(X2, X2, t6, curve_p); /* t3 = x3 */

	bn_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
	bn_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
	bn_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

	bn_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
	bn_modSub(t7, t7, t6, curve_p); /* t7 = x3' */
	bn_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
	bn_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
	bn_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */

	bn_set(X1, t7);
}
 void XYCZ_2w_addC(vec X1Y1[NLIMB / 2], vec X2Y2[NLIMB / 2], vec AT[NLIMB / 2])
 {
	 int i = 0;
	 uint64_t tmp1[NUM_DIGITS_SM2], tmp2[NUM_DIGITS_SM2];
	 uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB];
	 //<C,E>=<X2,Y1>*<A,T>
	 vec CE[NLIMB / 2] = { VZERO };
	 vec X2Y1[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离出<X2,Y1>
		 X2Y1[i] = BLEND32(X1Y1[i], X2Y2[i], 0XF0);
	 }
	 vec_2w_modmul(CE, X2Y1, AT);
	 /*
	 if (DEBUG)
	 {
		 printf("\nADDC\n");
		 vecto64(tmp1, tmp2, CE);
		 printf("C=X2*A:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("E=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<B,T1>=<C,Y2>-<T,Y1>
	 vec BT1[NLIMB / 2] = { VZERO }, CY2[NLIMB / 2] = { VZERO }, TY1[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 CY2[i] = BLEND32(X2Y2[i], CE[i], 0XF0);
		 TY1[i] = VPERM128(X1Y1[i], AT[i], 0X20);
		 //TY1[i] = BLEND32(VPERM64(AT[i], 0XEE), X1Y1[i], 0XF0);
	 }
	 vec_2w_sub(BT1, CY2, TY1);
	 vecto64(tmp1, tmp2, BT1);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(BT1, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("B=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T1=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<T2,T3>=<B,Y1>+<C,Y2>
	 vec T2T3[NLIMB / 2] = { VZERO }, BY1[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 BY1[i] = BLEND32(X1Y1[i], BT1[i], 0XF0);
	 }
	 vec_2w_add(T2T3, BY1, CY2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, T2T3);
		 printf("T2=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T3=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<D,F>=<T1,T3>^2  D=T1^2,F=T3^2
	 vec DF[NLIMB / 2] = { VZERO }, T1T3[NLIMB / 2] = { VZERO }, T1B[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 T1B[i] = VPERM64(BT1[i], 0X4E); //后面会用到，减少一次perm
		 T1T3[i] = BLEND32(T2T3[i], T1B[i], 0XF0);
	 }
	 vec_2w_modsqr(DF, T1T3);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, DF);
		 printf("D=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("F=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<X3,X3'>=<D,F>-<T2,T2>
	 vec X3X3_X3[NLIMB / 2] = { VZERO }, T2T2[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 T2T2[i] = VPERM64(T2T3[i], 0XEE);
	 }
	 vec_2w_sub(X3X3_X3, DF, T2T2);
	 //后面
	 vecto64(tmp1, tmp2, X3X3_X3);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(X3X3_X3, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("X3=D-T2:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("X3'=F-T2:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<T2,T4>=<B,X3_X3>-<X3,B>
	 vec T2T4[NLIMB / 2] = { VZERO }, BX3_X3[NLIMB / 2] = { VZERO }, X3B[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 BX3_X3[i] = BLEND32(X3X3_X3[i], BT1[i], 0XF0);
		 X3B[i] = BLEND32(T1B[i], X3X3_X3[i], 0XF0);
	 }
	 vec_2w_sub(T2T4, BX3_X3, X3B);
	 vecto64(tmp1, tmp2, T2T4);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(T2T4, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("T2=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T4=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<T2,T3>=<T1,T3>*<T2,T4>
	 vec_2w_modmul(T2T3, T1T3, T2T4);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 vecto64(tmp1, tmp2, T2T3);
		 printf("T2=T1*T2:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("T3=T3*T4:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
	 //<Y3,Y3_Y3>=<T2,T3>-<E,E>
	 vec Y3Y3_Y3[NLIMB / 2] = { VZERO }, EE[NLIMB / 2] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 EE[i] = VPERM64(CE[i], 0X44);
	 }
	 vec_2w_sub(Y3Y3_Y3, T2T3, EE);
	 vecto64(tmp1, tmp2, Y3Y3_Y3);
	 radix64to26(v_tmp1, tmp1);
	 radix64to26(v_tmp2, tmp2);
	 set_vector(Y3Y3_Y3, v_tmp1, v_tmp2);
	 /*
	 if (DEBUG)
	 {
		 printf("\n");
		 printf("Y3=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 printf("Y3'=:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */

	 //最终结果  in place
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //分离
		 X1Y1[i] = VPERM128(Y3Y3_Y3[i], X3X3_X3[i], 0X20);  //<X1,Y1>=<X3'Y3'>=P-Q
		 X2Y2[i] = VPERM128(Y3Y3_Y3[i], X3B[i], 0X31);//<X2,Y2>=<X3,Y3>=P+Q
	 }
	 /*
	 if (DEBUG)
	 {
		 vecto64(tmp1, tmp2, X1Y1);
		 printf("\n");
		 printf("<X1,Y1>=<X3',Y3'>:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
		 vecto64(tmp1, tmp2, X2Y2);
		 printf("<X2,Y2>=<X3,Y3>:\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp1[i]);
		 printf("\n");
		 for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			 printf("%llx ", tmp2[i]);
		 printf("\n");
	 }
	 */
 }
 void EccPoint_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ)
 {
	 /* R0 and R1 */
	 uint64_t Rx[2][NUM_DIGITS_SM2];
	 uint64_t Ry[2][NUM_DIGITS_SM2];
	 uint64_t z[NUM_DIGITS_SM2];
	 int i, nb;

	 bn_set(Rx[1], p_point->x);
	 bn_set(Ry[1], p_point->y);

	 XYCZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

	 for (i = bn_numBits(p_scalar) - 2; i > 0; --i)
	 {
		 nb = !bn_testBit(p_scalar, i);
		 XYCZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
		 XYCZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
	 }

	 nb = !bn_testBit(p_scalar, 0);
	 XYCZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

	 /* final 1/Z value. */
	 bn_modSub(z, Rx[1], Rx[0], curve_p); 
	 bn_modMult_fast(z, z, Ry[1 - nb]);  
	 bn_modMult_fast(z, z, p_point->x);  
	 bn_modInv(z, z, curve_p);           
	 bn_modMult_fast(z, z, p_point->y);  
	 bn_modMult_fast(z, z, Rx[1 - nb]);    
	

	 XYCZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);

	 AFF2XYCZ(Rx[0], Ry[0], z);

	 bn_set(p_result->x, Rx[0]);
	 bn_set(p_result->y, Ry[0]);
 }
 void EccPoint_2w_mult(affpoint *p_result, affpoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ)
{
	/* R0 and R1 */
	uint64_t Rx[2][NUM_DIGITS_SM2];
	uint64_t Ry[2][NUM_DIGITS_SM2];
	uint64_t z[NUM_DIGITS_SM2];
	int i, nb;
	vec XY[2][NLIMB / 2] = { {VZERO},{VZERO} };
	uint64_t v_tmp1[NLIMB] = { 0 }, v_tmp2[NLIMB] = { 0 };
	uint64_t A_A[NUM_DIGITS_SM2], T_T[NUM_DIGITS_SM2], TMP[NUM_DIGITS_SM2];
	vec AT[NLIMB / 2] = { VZERO };

	bn_set(Rx[1], p_point->x);
	bn_set(Ry[1], p_point->y);

	XYCZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

	for (i = bn_numBits(p_scalar) - 2; i > 0; --i)
	{
		nb = !bn_testBit(p_scalar, i);
		//只在第一轮转换为向量
		if (i == bn_numBits(p_scalar) - 2)
		{
			//Rxy[1-nb]=<X1,Y1>  Rxy[nb]=<X2,Y2>
			//要运算的点映射到256bit寄存器
			//1.XIY1X2Y2（长度为NUM_DIGITS_SM2数组）转换为长度为NLIMB的数组
			radix64to26(v_tmp1, Rx[1 - nb]);
			radix64to26(v_tmp2, Ry[1 - nb]);
			//2.将数组中的元素放入vec向量中
			set_vector(XY[1 - nb], v_tmp1, v_tmp2);

			radix64to26(v_tmp1, Rx[nb]);
			radix64to26(v_tmp2, Ry[nb]);
			set_vector(XY[nb], v_tmp1, v_tmp2);
		}
		//ADDC每个loop的预计算值A',T'    常规数组实现  
		bn_modSub(TMP, Rx[nb], Rx[1 - nb], curve_p);/*TMP=(X2-X1)*/
		bn_modSquare_fast(A_A, TMP);/*A'=(X2-X1)^2*/
		bn_modMult_fast(T_T, TMP, A_A);/*T'=(X2-X1)*A'*/
		//预计算正确
		//转换为向量AT=<A',T'>
		radix64to26(v_tmp1, A_A);
		radix64to26(v_tmp2, T_T);
		set_vector(AT, v_tmp1, v_tmp2);
	
		//ladder step
		XYCZ_2w_addC(XY[1-nb],XY[nb],AT);
		XYCZ_2w_add(XY[nb], XY[1-nb]);

		//为下个loop/loop外的AT预计算做准备
		vecto64(Rx[1 - nb], Ry[1 - nb], XY[1 - nb]);
		vecto64(Rx[nb], Ry[nb], XY[nb]);
	}
	
	nb = !bn_testBit(p_scalar, 0);
	//ADDC的预计算值A',T'    常规数组实现
	bn_modSub(TMP, Rx[nb], Rx[1 - nb], curve_p);//TMP=(X2-X1)
	bn_modSquare_fast(A_A, TMP);//A'=(X2-X1)^2
	bn_modMult_fast(T_T, TMP, A_A);//T'=(X2-X1)*A'
	//转换为向量AT=<A',T'>
	radix64to26(v_tmp1, A_A);
	radix64to26(v_tmp2, T_T);
	set_vector(AT, v_tmp1, v_tmp2);
	XYCZ_2w_addC(XY[1 - nb], XY[nb], AT);

	//<X1,Y1><X2,Y2>转换为radix64表示   X1Y1,X2Y2最长为29bit（乘法约减之后进行一次加/减）
	vecto64(Rx[1 - nb], Ry[1 - nb], XY[1 - nb]);
	vecto64(Rx[nb], Ry[nb], XY[nb]);
	/* Find final 1/Z value. */
	bn_modSub(z, Rx[1], Rx[0], curve_p);
	bn_modMult_fast(z, z, Ry[1 - nb]);  
	bn_modMult_fast(z, z, p_point->x);  
	bn_modInv(z, z, curve_p);            
	bn_modMult_fast(z, z, p_point->y);   
	bn_modMult_fast(z, z, Rx[1 - nb]);   
	/* End 1/Z calculation */

	XYCZ_2w_add(XY[nb], XY[1 - nb]);
	//<X1,Y1><X2,Y2>转换为radix64表示
	vecto64(Rx[1 - nb], Ry[1 - nb], XY[1 - nb]);
	vecto64(Rx[nb], Ry[nb], XY[nb]);
	//转换为仿射坐标
	AFF2XYCZ(Rx[0], Ry[0], z);
	//最终结果
	bn_set(p_result->x, Rx[0]);
	bn_set(p_result->y, Ry[0]);
}
 
#include"timing.h"

void timing_sm2()
{
	uint64_t x[NUM_DIGITS_SM2], y[NUM_DIGITS_SM2], z[NUM_DIGITS_SM2];
	//数字签名
	uint8_t p_hash[SM2_BYTES] = {
		0XF0,0XB4,0X3E,0X94,
		0XBA,0X45,0XAC,0XCA,
		0XAC,0XE6,0X92,0XED,
		0X53,0X43,0X82,0XEB,
		0X17,0XE6,0XAB,0X5A,
		0X19,0XCE,0X7B,0X31,
		0XF4,0X48,0X6F,0XDF,
		0XC0,0XD2,0X86,0X40 }, p_sign[SM2_BYTES * 2];
	//公钥加密,固定明文长度
	uint8_t cypher[SM2_BYTES * 2 + 19 + SM3_DIGEST_LENGTH];
	uint8_t plain[20] = { 0x65,0x6e,0x63,0x72,0x79,0x70,0x74,0x69,0x6f,0x6e,0x20,0x73,0x74,0x61,0x6e,0x64,0x61,0x72,0x64 };
	uint8_t plain1[20] = { 0 };
	//1-way
	//密钥生成
	uint8_t p_sk[SM2_BYTES], p_pk_X[SM2_BYTES], p_pk_Y[SM2_BYTES];
	int TEST_TIMES = 10;
	printf("--------------------timing 1-way SM2--------------------\n");
	test_function(TEST_TIMES, "1w_Key_Generation", sm2_make_key(p_sk, p_pk_X, p_pk_Y));
	test_function(TEST_TIMES, "1w_Signature_Generation", sm2_sign(p_sk, p_hash, p_sign));
	test_function(TEST_TIMES, "1w_Signature_Verify", sm2_verify(p_pk_X, p_pk_Y, p_hash, p_sign));
	test_function(TEST_TIMES, "1w_Encryption", sm2_encrypt(p_pk_X, p_pk_Y, plain, 19, cypher));
	test_function(TEST_TIMES, "1w_Decryption", sm2_decrypt(p_sk, cypher, 19, plain1));
	

	//2-way
	//密钥生成
	printf("--------------------timing 2-way SM2--------------------\n");
	test_function(TEST_TIMES, "2w_Key_Generation", sm2_make_key_2w(p_sk, p_pk_X, p_pk_Y));
	test_function(TEST_TIMES, "2w_Signature_Generation", sm2_sign_2w(p_sk, p_hash, p_sign));
	test_function(TEST_TIMES, "2w_Signature_Verify", sm2_verify_2w(p_pk_X, p_pk_Y, p_hash, p_sign));
	test_function(TEST_TIMES, "2w_Encryption", sm2_encrypt_2w(p_pk_X, p_pk_Y, plain, 19, cypher));
	test_function(TEST_TIMES, "2w_Decryption", sm2_decrypt_2w(p_sk, cypher, 19, plain1));
}
void timing_fp_arith()
{
	
	uint64_t x[NUM_DIGITS_SM2], y[NUM_DIGITS_SM2], z[NUM_DIGITS_SM2], p[2 * NUM_DIGITS_SM2];
	//1-way
	//随机化输入
	getRandomNumber(x);
	getRandomNumber(y);
	getRandomNumber(z);
	getRandomNumber(p);
	getRandomNumber(p+NUM_DIGITS_SM2);
	printf("\n------------------------Timing 1-way Fp Arith-----------------\n");
	//1-way 
	int TEST_TIMES = 10000;
	test_function(TEST_TIMES, "1w_add", bn_modAdd(z, x, y, curve_p));
	test_function(TEST_TIMES, "1w_sub", bn_modSub(z, z, x, curve_p));
	test_function(TEST_TIMES, "1w_mul", bn_modMult_fast(z, z, x));
	test_function(TEST_TIMES, "1w_sqr", bn_modSquare_fast(z, z));
	test_function(TEST_TIMES, "1w_inv", bn_modInv(z, z, curve_p));
	test_function(TEST_TIMES, "1w_red", bn_mmod_fast(x, p));

	//2-way
	//随机化输入向量
	vec a[NLIMB / 2], b[NLIMB / 2], r[NLIMB / 2], c[NLIMB];
	uint64_t tmp1[NUM_DIGITS_SM2], tmp2[NUM_DIGITS_SM2];
	uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB];
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(a, v_tmp1, v_tmp2);
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(b, v_tmp1, v_tmp2);
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(r, v_tmp1, v_tmp2);
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(c, v_tmp1, v_tmp2);
	set_vector(c+5, v_tmp1, v_tmp2);
	printf("\n------------------------Timing 2-way Fp Arith-----------------\n");
	test_function(TEST_TIMES, "2w_add", vec_2w_add(r, a, b));
	test_function(TEST_TIMES, "2w_sub", vec_2w_sub(r, r, a));
	test_function(TEST_TIMES, "2w_mul", vec_2w_modmul(r, r, a));
	test_function(TEST_TIMES, "2w_sqr", vec_2w_modsqr(r, r));
	test_function(TEST_TIMES, "2w_red", vec_2w_fastred(r, c));
}
void timing_point_arith()
{
	//1-way
	uint64_t x1[NUM_DIGITS_SM2], y1[NUM_DIGITS_SM2], x2[NUM_DIGITS_SM2], y2[NUM_DIGITS_SM2];
	//随机化输入
	getRandomNumber(x1);
	getRandomNumber(y1);
	getRandomNumber(x2);
	getRandomNumber(y2);
	affpoint p, q;
	uint64_t scalar[NUM_DIGITS_SM2];
	getRandomNumber(scalar);
	getRandomNumber(p.x);
	getRandomNumber(p.y);
	getRandomNumber(q.x);
	getRandomNumber(q.y);
	int TEST_TIMES = 10000;
	printf("\n------------------------Timing 1-way Point Arith-----------------\n");
	test_function(TEST_TIMES, "1w_Point_ADD", XYCZ_add(x1, y1, x2, y2));
	test_function(TEST_TIMES, "1w_Point_ADDC", XYCZ_addC(x1, y1, x2, y2));
	TEST_TIMES = 100;
	test_function(TEST_TIMES, "1w_Montgomery_ladder", EccPoint_mult(&p, &q, scalar, NULL));
	//2-way
	vec x1y1[NLIMB / 2], x2y2[NLIMB / 2];
	uint64_t tmp1[NUM_DIGITS_SM2], tmp2[NUM_DIGITS_SM2];
	uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB];
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(x1y1, v_tmp1, v_tmp2);
	getRandomNumber(tmp1);
	getRandomNumber(tmp2);
	radix64to26(v_tmp1, tmp1);
	radix64to26(v_tmp2, tmp2);
	set_vector(x2y2, v_tmp1, v_tmp2);
	uint64_t TMP[NUM_DIGITS_SM2], A_A[NUM_DIGITS_SM2], T_T[NUM_DIGITS_SM2];
	uint64_t v_A[NLIMB], v_T[NLIMB];
	vec AT[NLIMB / 2];
	bn_modSub(TMP, x2, x1, curve_p);//TMP=(X2-X1)
	bn_modSquare_fast(A_A, TMP);//A'=(X2-X1)^2
	bn_modMult_fast(T_T, TMP, A_A);//T'=(X2-X1)*A'
	radix64to26(v_A, A_A);
	radix64to26(v_T, T_T);
	set_vector(AT, v_A, v_T);
	TEST_TIMES = 10000;
	printf("\n------------------------Timing 2-way Point Arith-----------------\n");
	test_function(TEST_TIMES, "2w_Point_ADD", XYCZ_2w_add(x1y1, x2y2));
	test_function(TEST_TIMES, "2w_Point_ADDC", XYCZ_2w_addC(x1y1, x2y2, AT));
	TEST_TIMES = 100;
	test_function(TEST_TIMES, "2w_Montgomery_ladder", EccPoint_2w_mult(&p, &q, scalar, NULL));
}
void timing_part()
{
	//1-way
	int TEST_TIMES;
	affpoint p, q;
	uint64_t scalar[NUM_DIGITS_SM2], x[NUM_DIGITS_SM2], y[NUM_DIGITS_SM2], z[NUM_DIGITS_SM2];
	getRandomNumber(x);
	getRandomNumber(y);
	getRandomNumber(z);
	getRandomNumber(scalar);
	getRandomNumber(p.x);
	getRandomNumber(p.y);
	getRandomNumber(q.x);
	getRandomNumber(q.y);
	printf("\n-------------------1w_sm2_part--------------------\n");
	printf("\n-------Digital Signature-------\n");
	
	printf("\n------Signature-----\n");
	//A4,1个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "1w_Point_Mul", EccPoint_mult(&p, &q, scalar, NULL));
	//A5+A6,3个模加
	TEST_TIMES = 10000;
	test_function(TEST_TIMES, "3_1w_Mod_Add", bn_modAdd(z, x, y, curve_p));
	//A6,1个模逆，1个模乘
	test_function(TEST_TIMES, "1w_Mod_Mul", bn_modMult_fast(z, z, x));
	test_function(TEST_TIMES, "1w_Mod_Inv", bn_modInv(z, z, curve_p));
	printf("\n-------Vignature------\n");
	//B5+B7,2个模加
	test_function( 2 * TEST_TIMES, "2_1w_Mod_Add", bn_modAdd(z, x, y, curve_p));
	//B6,sG + tPA
	affpoint l_sum;
	uint64_t tx[NUM_DIGITS_SM2],ty[NUM_DIGITS_SM2], rx[NUM_DIGITS_SM2], ry[NUM_DIGITS_SM2], tz[NUM_DIGITS_SM2];
	uint64_t l_s[NUM_DIGITS_SM2], l_t[NUM_DIGITS_SM2];
	getRandomNumber(l_s);
	getRandomNumber(l_t);
	bn_set(l_sum.x, p.x);
	bn_set(l_sum.y, p.y);
	//t=G
	bn_set(tx, curve_G.x);
	bn_set(ty, curve_G.y);
	bn_modSub(z, l_sum.x, tx, curve_p); //z=sum.x-t.x-----PA.x-G.x
	XYCZ_add(tx, ty, l_sum.x, l_sum.y);//sum=sum+t---------PA+G
	bn_modInv(z, z, curve_p);
	AFF2XYCZ(l_sum.x, l_sum.y, z);
	/* Use Shamir's trick to calculate s*G + t*Q */
	affpoint* l_points[4] = { NULL, &curve_G, &p, &l_sum };
	unsigned int l_numBits = umax(bn_numBits(l_s), bn_numBits(l_t));
	affpoint* l_point = l_points[(!!bn_testBit(l_s, l_numBits - 1)) | ((!!bn_testBit(l_t, l_numBits - 1)) << 1)];
	bn_set(rx, l_point->x);
	bn_set(ry, l_point->y);
	bn_init0(z);
	z[0] = 1;
	int i;
	uint64_t start_time, end_time;
	start_time = GetTickCount64();
	for (i = l_numBits - 2; i >= 0; --i)
	{
		EccPoint_double_jacobian(rx, ry, z);
		int l_index = (!!bn_testBit(l_s, i)) | ((!!bn_testBit(l_t, i)) << 1);
		affpoint* l_point = l_points[l_index];
		if (l_point)
		{
			bn_set(tx, l_point->x);
			bn_set(ty, l_point->y);
			AFF2XYCZ(tx, ty, z);
			bn_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
			XYCZ_add(tx, ty, rx, ry);
			bn_modMult_fast(z, z, tz);
		}
	}
	bn_modInv(z, z, curve_p); /* Z = 1/Z */
	AFF2XYCZ(rx, ry, z);
	/* x1 = x1 (mod n) */
	while (bn_cmp(curve_n, rx) != 1)
	{
		bn_sub(rx, rx, curve_n);
	}	
	end_time = GetTickCount64();
	printf("timing sG + tPA\n");
	printf("  - Total time : %lld ms\n", end_time - start_time);
	printf("  - Throughput: %8.1f op/sec\n", 1e3  / (double)(end_time - start_time));
	
	//公钥加密
	uint8_t t1[SM2_BYTES], t2[SM2_BYTES], Z[SM2_BYTES * 2],C3[SM3_DIGEST_LENGTH];
	uint8_t M[20] = { 0x65,0x6e,0x63,0x72,0x79,0x70,0x74,0x69,0x6f,0x6e,0x20,0x73,0x74,0x61,0x6e,0x64,0x61,0x72,0x64 };
	int mlen = 19;
	ecc_native2bytes(t1, x);
	ecc_native2bytes(t2, y);
	memcpy(Z, t1, SM2_BYTES);
	memcpy(Z + SM2_BYTES, t2, SM2_BYTES);
	memcpy(C3, Z, SM3_DIGEST_LENGTH);
	uint8_t* H = (uint8_t*)malloc(sizeof(uint8_t) * (SM2_BYTES * 2 + mlen));
	memcpy(H, t1, SM2_BYTES);
	memcpy(H + SM2_BYTES, M, mlen);
	memcpy(H + SM2_BYTES + mlen, t2, SM2_BYTES);
	printf("---------------Public Key Encryption----------\n");
	printf("\n------Encryption-----\n");
	//A2+A4：C1=kG=(x1,y1)  kPB  2个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "2_1w_Point_Mul", EccPoint_mult(&p, &q, scalar, NULL));
	//A5 KDF  mlen长度为19
	TEST_TIMES = 10000;
	test_function(TEST_TIMES, "KDF", sm2_kdf(Z, mlen));
	//A7 Hash
	test_function(TEST_TIMES, "Hash", sm3_hash(H, C3, SM2_BYTES * 2 + mlen));
	printf("\n------Decryption-----\n");
	//B3 dB*C1 1个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "1w_Point_Mul", EccPoint_mult(&p, &q, scalar, NULL));
	//B4 KDF
	TEST_TIMES = 1000;
	test_function(TEST_TIMES, "KDF", sm2_kdf(Z, mlen));
	//B6 Hash
	test_function(TEST_TIMES, "Hash", sm3_hash(H, C3, SM2_BYTES * 2 + mlen));
	
	//2-way
	printf("\n-------------------2w_sm2_part--------------------\n");
	printf("\n-------Digital Signature-------\n");
	printf("\n------Signature-----\n");
	//A4,1个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "2w_Point_Mul", EccPoint_2w_mult(&p, &q, scalar, NULL));
	//A5+A6,3个模加
	TEST_TIMES = 10000;
	test_function(TEST_TIMES, "3_1w_Mod_Add", bn_modAdd(z, x, y, curve_p));
	//A6,1个模逆，1个模乘
	test_function(TEST_TIMES, "1w_Mod_Mul", bn_modMult_fast(z, z, x));
	test_function(TEST_TIMES, "1w_Mod_Inv", bn_modInv(z, z, curve_p));
	printf("\n-------Vignature------\n");
	//B5+B7,2个模加
	test_function(TEST_TIMES, "2_1w_Mod_Add", bn_modAdd(z, x, y, curve_p));
	//B6,sG + tPA
	uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB];
	vec X1Y1[NLIMB / 2], X2Y2[NLIMB / 2];
	/* Use Shamir's trick to calculate s*G + t*Q */
	l_points[0] = NULL;
	l_points[1] = &curve_G;
	l_points[2] = &p;
	l_points[3] = &l_sum;
	l_numBits = umax(bn_numBits(l_s), bn_numBits(l_t));
	l_point = l_points[(!!bn_testBit(l_s, l_numBits - 1)) | ((!!bn_testBit(l_t, l_numBits - 1)) << 1)];
	bn_set(rx, l_point->x);
	bn_set(ry, l_point->y);
	bn_init0(z);
	z[0] = 1;
	start_time = GetTickCount64();
	for (i = l_numBits - 2; i >= 0; --i)
	{
		EccPoint_double_jacobian(rx, ry, z);

		int l_index = (!!bn_testBit(l_s, i)) | ((!!bn_testBit(l_t, i)) << 1);
		affpoint* l_point = l_points[l_index];
		if (l_point)
		{
			bn_set(tx, l_point->x);
			bn_set(ty, l_point->y);
			AFF2XYCZ(tx, ty, z);
			bn_modSub(tz, rx, tx, curve_p); // Z = x2 - x1 

			radix64to26(v_tmp1, tx);
			radix64to26(v_tmp2, ty);
			set_vector(X1Y1, v_tmp1, v_tmp2);
			radix64to26(v_tmp1, rx);
			radix64to26(v_tmp2, ry);
			set_vector(X2Y2, v_tmp1, v_tmp2);
			XYCZ_2w_add(X1Y1, X2Y2);
			//XYCZ_2w_add(tx, ty, rx, ry);
			vecto64(tx, ty, X1Y1);
			vecto64(rx, ry, X2Y2);

			bn_modMult_fast(z, z, tz);
		}
	}
	bn_modInv(z, z, curve_p); // Z = 1/Z 
	AFF2XYCZ(rx, ry, z);
	// x1 = x1 (mod n) 
	while (bn_cmp(curve_n, rx) != 1)
	{
		bn_sub(rx, rx, curve_n);
	}
	end_time = GetTickCount64();
	printf("timing sG + tPA\n");
	printf("  - Total time : %lld ms\n", end_time - start_time);
	printf("  - Throughput: %8.1f op/sec\n", 1e3  / (double)(end_time - start_time));

	//公钥加密
	printf("---------------Public Key Encryption----------\n");
	printf("\n------Encryption-----\n");
	//A2+A4：C1=kG=(x1,y1)  kPB  2个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "2_2w_Point_Mul", EccPoint_2w_mult(&p, &q, scalar, NULL));
	//A5 KDF  mlen长度为19
	TEST_TIMES = 10000;
	test_function(TEST_TIMES, "KDF", sm2_kdf(Z, mlen));
	//A7 Hash
	test_function(TEST_TIMES, "Hash", sm3_hash(H, C3, SM2_BYTES * 2 + mlen));
	printf("\n------Decryption-----\n");
	//B3 dB*C1 1个点乘
	TEST_TIMES = 10;
	test_function(TEST_TIMES, "2w_Point_Mul", EccPoint_2w_mult(&p, &q, scalar, NULL));
	//B4 KDF
	TEST_TIMES = 10000;
	test_function(TEST_TIMES, "KDF", sm2_kdf(Z, mlen));
	//B6 Hash
	test_function(TEST_TIMES, "Hash", sm3_hash(H, C3, SM2_BYTES * 2 + mlen));
	free(H);
}
void timing_all()
{

	printf("\n============================Timing Fp Arith==========================\n");
	timing_fp_arith();
	printf("\n==========================Timing Point Arith=========================\n");
	timing_point_arith();
	printf("\n===============================Timing SM2============================\n");
	timing_sm2();
	//论文测试算法关键步骤耗时
	//printf("\n----------------------SM2_part------------------------\n");
	//timing_part();

}
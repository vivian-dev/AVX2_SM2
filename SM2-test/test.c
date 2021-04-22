#include"test.h"
#define MAX_TRIES 16

void test_map(uint64_t *x, uint64_t *y)
{
	uint64_t arryx[NLIMB], arryy[NLIMB];
	vec XY[NLIMB / 2];
	radix64to26(arryx, x);
	radix64to26(arryy, y);
	set_vector(XY, arryx, arryy);
	for (int i = 0; i < NLIMB / 2; i++)
	{
		long long int* lo = (long long int*) & XY[i];
		printf("limb[%d]:%llx\  ", 2 * i, lo[2]);
		printf("limb[%d]:%llx\  ", 2 * i + 1, lo[3]);
	}
	printf("\n");
	for (int i = 0; i < NLIMB / 2; i++)
	{
		long long int* lo = (long long int*) & XY[i];
		printf("limb[%d]:%llx\  ", 2 * i, lo[0]);
		printf("limb[%d]:%llx\  ", 2 * i + 1, lo[1]);
	}
	printf("\n");
}

void test_1w_bignum(uint64_t* bn0, uint64_t* bn1, uint64_t* bn2, uint64_t* bn3)
{
	int i;
	uint64_t bnresult[NUM_DIGITS_SM2] = { 0,0,0,0 };
	printf("\n====================Test 1-way Fp Arith=================\n");
	printf("Big num as follow:\n");
	printf("p\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_p[i]);
	printf("\nbn0\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bn0[i]);
	printf("\nbn1\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bn1[i]);
	printf("\nbn2\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bn2[i]);
	printf("\nbn3\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bn3[i]);
	printf("\n-----------Mod_Add-----------\n");
	bn_modAdd(bnresult, bn0, bn1, curve_p);
	printf(" -bn0+bn1mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	bn_modAdd(bnresult, bn2, bn3, curve_p);
	printf("\n -bn2+bn3mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	printf("\n-----------Mod_Sub-----------\n");
	bn_modSub(bnresult, bn0, bn1, curve_p);
	printf(" -bn0-bn1mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	bn_modSub(bnresult, bn2, bn3, curve_p);
	printf("\n -bn2-bn3mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	printf("\n-----------Mod_Mul-----------\n");
	bn_modMult_fast(bnresult, bn0, bn1);
	printf(" -bn0*bn1mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	bn_modMult_fast(bnresult, bn2, bn3);
	printf("\n -bn2*bn3mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	printf("\n-----------Mod_Sqr-----------\n");
	bn_modSquare_fast(bnresult, bn0);
	printf(" -bn0^2mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	bn_modSquare_fast(bnresult, bn2);
	printf("\n -bn2^2mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
	printf("\n-----------Mod_Inv-----------\n");
	bn_modInv(bnresult, bn0, curve_p);
	printf("1/bn0 mod p\n");
	printf("  ");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", bnresult[i]);
}
void test_2w_bignum()
{
	int i = 0;
	uint64_t a[NUM_DIGITS_SM2], b[NUM_DIGITS_SM2], c[NUM_DIGITS_SM2], d[NUM_DIGITS_SM2];
	getRandomNumber(a);
	getRandomNumber(b);
	getRandomNumber(c);
	getRandomNumber(d);
	/*
	uint64_t a[NUM_DIGITS_SM2] = { 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,0xFFFFFFFFFFFFFFFFull, 0x4FFFFFFEFFFFFFFFull };
	uint64_t b[NUM_DIGITS_SM2] = { 0X1,0,0,0 };
	uint64_t c[NUM_DIGITS_SM2] = { 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,0xFFFFFFFFFFFFFFFFull, 0x4FFFFFFEFFFFFFFFull };
	uint64_t d[NUM_DIGITS_SM2] = { 0X1,0,0,0 };
	*/
	uint64_t arrya[NLIMB], arryb[NLIMB], arryc[NLIMB], arryd[NLIMB];
	uint64_t e[NUM_DIGITS_SM2], f[NUM_DIGITS_SM2];
	vec AB[NLIMB / 2], CD[NLIMB / 2], EF[NLIMB / 2];
	test_1w_bignum(a, c, b, d);
	radix64to26(arrya, a);
	radix64to26(arryb, b);
	set_vector(AB, arrya, arryb);
	radix64to26(arryc, c);
	radix64to26(arryd, d);
	set_vector(CD, arryc, arryd);
	printf("\n\n====================Test 2-way Fp Arith=================\n");
	printf("Vector as follow\n");
	printf("<a,b> limbs\n");
	test_map(a, b);
	printf("<c,d> limbs\n");
	test_map(c, d);
	printf("-----------Mod_Add-----------\n");
	vec_2w_add(EF, AB, CD); 
	vecto64(e, f, EF);
	printf(" -<E,F>=<A,B>+<C,D>,e=a+c,f=b+d\n");
	printf(" -e:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", e[i]);
	printf("\n -f:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", f[i]);

	printf("\n-----------Mod_Sub-----------\n");
	vec_2w_sub(EF, AB, CD);
	vecto64(e, f, EF);
	printf(" -<E,F>=<A,B>-<C,D>,e=a-c,f=b-d\n");
	printf(" -e:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", e[i]);
	printf("\n -f:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", f[i]);

	printf("\n-----------Mod_Mul-----------\n");
	vec_2w_modmul(EF, AB, CD);
	vecto64(e, f, EF);
	printf(" -<E,F>=<A,B><C,D>,e=ac,f=bd\n");
	printf(" -e:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", e[i]);
	printf("\n -f:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", f[i]);
	printf("\n-----------Mod_Sqr-----------\n");
	vec_2w_modsqr(EF, AB);
	vecto64(e, f, EF);
	printf(" -<E,F>=<A,B>^2,e=a^2,f=b^2\n");
	printf(" -e:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", e[i]);
	printf("\n -f:");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", f[i]);
}
void test_pointmul()
{
	uint8_t p_privateKey[SM2_BYTES], p_publicKey_X[SM2_BYTES], p_publicKey_Y[SM2_BYTES];
	uint64_t l_private[NUM_DIGITS_SM2];
	affpoint l_public,l_1w_public;
	unsigned l_tries = 0;
	int i;
	do
	{
		if (!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(l_private))
		{
			continue;
		}
		/* Make sure the private key is in the range [1, n-1].
		   For the supported curves, n is always large enough that we only need to subtract once at most. */
		if (bn_cmp(curve_n, l_private) != 1)
		{
			bn_sub(l_private, l_private, curve_n);
		}
		EccPoint_2w_mult(&l_public, &curve_G, l_private, NULL);
	} while (EccPoint_isZero(&l_public));
	//测试1-way
	EccPoint_mult(&l_1w_public, &curve_G, l_private, NULL);
	printf("\n=================Test 1w_PointMul===============\n");
	ecc_native2bytes(p_privateKey, l_private);
	print_sk(p_privateKey);
	ecc_native2bytes(p_publicKey_X, l_1w_public.x);
	ecc_native2bytes(p_publicKey_Y, l_1w_public.y);
	printf(" -Result of Scalar Multiplication\n");
	print_affpoint(p_publicKey_X, p_publicKey_Y);

	printf("\n=================Test 2w_PointMul===============\n");
	ecc_native2bytes(p_publicKey_X, l_public.x);
	ecc_native2bytes(p_publicKey_Y, l_public.y);
	print_sk(p_privateKey);
	printf(" -Result of Scalar Multiplication\n");
	print_affpoint(p_publicKey_X, p_publicKey_Y);
}
void test_2w_sm2()
{
	int i = 0;
	uint8_t p_sk[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t p_pk_X[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t p_pk_Y[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	int pid = 0;
	printf("\n\n=========================Test 2w_sm2=======================\n");
	printf("------------------2w_SM2_Key_Generation----------------\n");
	pid = sm2_make_key_2w(p_sk, p_pk_X, p_pk_Y);
	if (pid == 1)
	{
		printf(" -Key pair generate success!\n");
		print_sk(p_sk);
		printf(" -Public key(byte)\n");
		print_affpoint(p_pk_X, p_pk_Y);
	}
	else
		printf("\n -Key pair generate fail!\n");
	printf("-----------------2w_SM2_Digital_Signature-------------\n");
	uint8_t p_sign[SM2_BYTES * 2];
	//参考SM2第五部分
	uint8_t p_hash[SM2_BYTES] = {
		0XF0,0XB4,0X3E,0X94,
		0XBA,0X45,0XAC,0XCA,
		0XAC,0XE6,0X92,0XED,
		0X53,0X43,0X82,0XEB,
		0X17,0XE6,0XAB,0X5A,
		0X19,0XCE,0X7B,0X31,
		0XF4,0X48,0X6F,0XDF,
		0XC0,0XD2,0X86,0X40 };
	printf(">>>>>>User A Generate Signature<<<<<<\n");
	pid = sm2_sign_2w(p_sk, p_hash, p_sign);
	if (pid == 1)
	{
		printf(" >Signature generate success!\n");
		print_sign(p_sign);
	}
	else
		printf("\n >Signature generate success!");
	printf(">>>>>>User B Verify Signature<<<<<<\n");

	pid = sm2_verify_2w(p_pk_X, p_pk_Y, p_hash, p_sign);
	if (pid == 1)
	{
		printf(" >Verify success!\n");
	}
	else
		printf(" > Verify fail!\n");
	printf("--------------2w_SM2_Public_Key_Encryption------------\n");
	unsigned char plain[200]="0";
	FILE* fp;
	fp = fopen("plain.txt", "r+");
	fgets(plain, 200, fp);
	fclose(fp);
	int mlen = strlen(plain);
	unsigned char* cypher= (unsigned char*)malloc(sizeof(unsigned char) * (SM2_BYTES * 2 + mlen + SM3_DIGEST_LENGTH));
	unsigned char* plain1 = (unsigned char*)malloc(sizeof(unsigned char) * (mlen+1));
	//修改SM2明文格式
	printf(">>>>>>User A Encrypt<<<<<<\n");
	printf(" >Plaintext as follow\n");
	printf("  (string)%s\n", plain);
	printf("  (byte)");
	for (i = 0; i < mlen; i++)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
	pid = sm2_encrypt_2w(p_pk_X, p_pk_Y, plain, mlen, cypher);//加密消息字节长度
	if (pid)
	{
		printf(" >Encrypt success,ciphertext as follow\n");
		//printf("%s\n", cypher);
		printf(" >C1:\n");
		printf("  ");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		printf("  ");
		for (i = SM2_BYTES; i < SM2_BYTES * 2; i++)
		{
			printf("%02x ", cypher[i]);

		}
		printf("\n");
		printf(" >C2:\n");
		printf("  ");
		for (i = SM2_BYTES * 2; i < SM2_BYTES * 2 + mlen;i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		printf(" >C3:\n");
		printf("  ");
		for (i = SM2_BYTES * 2 + mlen; i < SM2_BYTES * 2 + mlen + SM3_DIGEST_LENGTH; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
	}
	else
	{
		printf("\n >Encrypt fail!\n");
	}
	printf(">>>>>>User B Decrypt<<<<<<\n");
	pid = sm2_decrypt_2w(p_sk, cypher, mlen, plain1);
	plain1[mlen] = '\0';
	if (pid)
	{
		printf(" >Decrypt success,plaintext as follow\n");
		printf("  (string)%s\n", plain1);
		printf("  (byte)");
		for (int i = 0; i < mlen; i++)
		{
			printf("%02x ", plain1[i]);
		}
	}
	else
	{
		printf(" >Decrypt fail!\n");
		
	}
	free(plain1);
	free(cypher);
}
void test_1w_sm2()
{
	int i = 0;
	uint8_t p_sk[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t p_pk_X[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t p_pk_Y[SM2_BYTES] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	int pid = 0;
	printf("\n=========================Test 1w_sm2=======================\n");
	printf("---------------------1w_SM2_Key_Generation--------------\n");
	pid = sm2_make_key(p_sk, p_pk_X, p_pk_Y);
	if (pid == 1)
	{
		printf(" -Key pair generate success!\n");
		print_sk(p_sk);
		printf(" -Public key(byte)\n");
		print_affpoint(p_pk_X, p_pk_Y);
	}
	else
		printf("\n -Key pair generate fail!\n");
	printf("-------------------1w_SM2_Digital_Signature------------\n");
	uint8_t p_sign[SM2_BYTES * 2];
	//参考SM2第五部分
	uint8_t p_hash[SM2_BYTES] = {
		0XF0,0XB4,0X3E,0X94,
		0XBA,0X45,0XAC,0XCA,
		0XAC,0XE6,0X92,0XED,
		0X53,0X43,0X82,0XEB,
		0X17,0XE6,0XAB,0X5A,
		0X19,0XCE,0X7B,0X31,
		0XF4,0X48,0X6F,0XDF,
		0XC0,0XD2,0X86,0X40 };
	printf(">>>>>>User A Generate Signature<<<<<<\n");
	pid = sm2_sign(p_sk, p_hash, p_sign);
	if (pid == 1)
	{
		printf(" >Signature generate success!\n");
		print_sign(p_sign);
	}
	else
		printf("\n >Signature generate success!");

	printf(">>>>>>User B Verify Signature<<<<<<\n");
	pid = sm2_verify(p_pk_X, p_pk_Y, p_hash, p_sign);
	if (pid == 1)
	{
		printf(" >Verify success!\n");
	}
	else
		printf(" > Verify fail!\n");

	printf("---------------1w_SM2_Public_Key_Encryption------------\n");
	unsigned char plain[200] = "0";
	FILE* fp;
	fp = fopen("plain.txt", "r+");
	fgets(plain, 200, fp);
	fclose(fp);
	int mlen = strlen(plain);
	unsigned char* cypher = (unsigned char*)malloc(sizeof(unsigned char) * (SM2_BYTES * 2 + mlen + SM3_DIGEST_LENGTH));
	unsigned char* plain1 = (unsigned char*)malloc(sizeof(unsigned char) * (mlen + 1));
	printf(">>>>>>User A Encrypt<<<<<<\n");
	printf(" >Plaintext as follow\n");
	printf("  (string)%s\n", plain);
	printf("  (byte)");
	for (i = 0; i < mlen; i++)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
	pid = sm2_encrypt(p_pk_X, p_pk_Y, plain, mlen, cypher);//加密消息字节长度
	if (pid)
	{
		printf(" >Encrypt success,ciphertext as follow\n");
		printf(" >C1:\n");
		printf("  ");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", cypher[i]);
		printf("\n");
		printf("  ");
		for (i = SM2_BYTES; i < SM2_BYTES * 2; i++)
			printf("%02x ", cypher[i]);
		printf("\n");
		printf(" >C2:\n");
		printf("  ");
		for (i = SM2_BYTES * 2; i < SM2_BYTES * 2 + mlen; i++)
			printf("%02x ", cypher[i]);
		printf("\n");
		printf(" >C3:\n");
		printf("  ");
		for (i = SM2_BYTES * 2 + mlen; i < SM2_BYTES * 2 + mlen + SM3_DIGEST_LENGTH; i++)
			printf("%02x ", cypher[i]);
		printf("\n");
	}
	else
	{
		printf("\n >Encrypt fail!\n");
	}
	printf(">>>>>>User B Decrypt<<<<<<\n");
	pid = sm2_decrypt(p_sk, cypher, mlen, plain1);
	plain1[mlen] = '\0';
	if (pid)
	{
		printf(" >Decrypt success,plaintext as follow\n");
		printf("  (string)%s\n", plain1);
		printf("  (byte)");
		for (int i = 0; i < mlen; i++)
		{
			printf("%02x ", plain1[i]);
		}
	}
	else
	{
		printf(" >Decrypt fail!\n");
	}
	free(plain1);
	free(cypher);
}
void test_all()
{
	printf("\n----------------------------Test Fp Arith---------------------\n");
	test_2w_bignum(); //测试2-way大整数运算正确性，包含1-way的对照
	printf("\n\n------------------------Test Point Arith----------------------\n");
	test_pointmul();  //测试2-way标量乘法,包含1-way对照
	printf("\n-------------------------Test SM2-----------------------------\n");
	test_1w_sm2();
	test_2w_sm2();
}
//SM2上层协议实现
#include"sm2.h"
#include"sm3.h"
#define MAX_TRIES 16
#define DEBUG 0
extern uint64_t curve_p[NUM_DIGITS_SM2] = { 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull };
extern uint64_t curve_b[NUM_DIGITS_SM2] = { 0xDDBCBD414D940E93ull, 0xF39789F515AB8F92ull, 0x4D5A9E4BCF6509A7ull, 0x28E9FA9E9D9F5E34ull };
extern uint64_t curve_a[NUM_DIGITS_SM2] = { 0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFF00000000ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull };
extern affpoint curve_G = {
   {0x715A4589334C74C7ull, 0x8FE30BBFF2660BE1ull, 0x5F9904466A39C994ull, 0x32C4AE2C1F198119ull},
   {0x02DF32E52139F0A0ull, 0xD0A9877CC62A4740ull, 0x59BDCEE36B692153ull, 0xBC3736A2F4F6779Cull} };
extern uint64_t curve_n[NUM_DIGITS_SM2] = { 0x53BBF40939D54123ull,0x7203DF6B21C6052Bull,0xFFFFFFFFFFFFFFFFull,0xFFFFFFFEFFFFFFFFull };


//Windows下产生随机数
#if (defined(_WIN32) || defined(_WIN64))
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

int getRandomNumber(uint64_t *p_bn)
{
	HCRYPTPROV l_prov;
	if (!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		return 0;
	}

	CryptGenRandom(l_prov, SM2_BYTES, (BYTE *)p_bn);
	CryptReleaseContext(l_prov, 0);

	return 1;
}

#else 
/* Assume that we are using a POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int getRandomNumber(uint64_t *p_bn)
{
	int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (l_fd == -1)
	{
		l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
		if (l_fd == -1)
		{
			return 0;
		}
	}

	char *l_ptr = (char *)p_bn;
	size_t l_left = SM2_BYTES;
	while (l_left > 0)
	{
		int l_read = read(l_fd, l_ptr, l_left);
		if (l_read <= 0)
		{ // read failed
			close(l_fd);
			return 0;
		}
		l_left -= l_read;
		l_ptr += l_read;
	}

	close(l_fd);
	return 1;
}

#endif /* _WIN32 */

int sm2_make_key(uint8_t p_privateKey[SM2_BYTES], uint8_t p_publicKey_X[SM2_BYTES], uint8_t p_publicKey_Y[SM2_BYTES])
{
	uint64_t l_private[NUM_DIGITS_SM2] = { 0X42FB81EF4DF7C5B8ULL,0X0889393692860B51AULL,0X3F36E38AC6D39F95ULL,0X3945208F7B2144B1ULL };
	affpoint l_public;
	unsigned l_tries = 0;
	int i;
	do
	{
		/*
		if (!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(l_private))
		{
			continue;
		}
		*/
		/* Make sure the private key is in the range [1, n-1].
		   For the supported curves, n is always large enough that we only need to subtract once at most. */
		/*
		if (bn_cmp(curve_n, l_private) != 1)
		{
			bn_sub(l_private, l_private, curve_n);
		}
		*/
		EccPoint_mult(&l_public, &curve_G, l_private, NULL);
	} while (EccPoint_isZero(&l_public));
	ecc_native2bytes(p_privateKey, l_private);
	if (p_publicKey_X != NULL)
		ecc_native2bytes(p_publicKey_X, l_public.x);
	else return 0;
	if (p_publicKey_Y != NULL)
		ecc_native2bytes(p_publicKey_Y, l_public.y);
	else return 0;
	return 1;
}
int sm2_make_key_2w(uint8_t p_privateKey[SM2_BYTES], uint8_t p_publicKey_X[SM2_BYTES], uint8_t p_publicKey_Y[SM2_BYTES])
{
	uint64_t l_private[NUM_DIGITS_SM2] = { 0X42FB81EF4DF7C5B8ULL,0X0889393692860B51AULL,0X3F36E38AC6D39F95ULL,0X3945208F7B2144B1ULL };
	affpoint l_public;
	unsigned l_tries = 0;
	int i;
	do
	{
		/*
		if (!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(l_private))
		{
			continue;
		}
		*/
		/* Make sure the private key is in the range [1, n-1].
		   For the supported curves, n is always large enough that we only need to subtract once at most. */
		/*
		if (bn_cmp(curve_n, l_private) != 1)
		{
			bn_sub(l_private, l_private, curve_n);
		}
		*/
		//验证
		/*
		printf("\n私钥（64bit形式）\n");
		for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
			printf("%llx ", l_private[i]);
			*/
		EccPoint_2w_mult(&l_public, &curve_G, l_private, NULL);
	} while (EccPoint_isZero(&l_public));
	//验证
	/*
	printf("\n公钥（64bit形式）\n");
	printf("\nX坐标\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%llx ", l_public.x[i]);
	printf("\nY坐标\n");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%llx ", l_public.y[i]);
	*/
	ecc_native2bytes(p_privateKey, l_private);
	//    ecc_native2bytes(p_publicKey + 1, l_public.x);
	//    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
	if (p_publicKey_X != NULL)
		ecc_native2bytes(p_publicKey_X, l_public.x);
	else return 0;
	if (p_publicKey_Y != NULL)
		ecc_native2bytes(p_publicKey_Y, l_public.y);
	else return 0;
	return 1;
}
int sm2_shared_secret(const uint8_t p_publicKey[SM2_BYTES + 1], const uint8_t p_privateKey[SM2_BYTES], uint8_t p_secret[SM2_BYTES])
{
	affpoint l_public;
	uint64_t l_private[NUM_DIGITS_SM2];
	uint64_t l_random[NUM_DIGITS_SM2];

	if (!getRandomNumber(l_random))
	{
		return 0;
	}

	ecc_point_decompress(&l_public, p_publicKey);
	ecc_bytes2native(l_private, p_privateKey);

	affpoint l_product;
	EccPoint_mult(&l_product, &l_public, l_private, l_random);

	ecc_native2bytes(p_secret, l_product.x);

	return !EccPoint_isZero(&l_product);
}
int sm2_sign(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2])
{
	uint8_t tmp1x[SM2_BYTES], tmp1y[SM2_BYTES], tmp[SM2_BYTES];
	uint8_t tmpx[SM2_BYTES];
	uint8_t tmpy[SM2_BYTES];
	uint8_t tmp1[SM2_BYTES];
	uint8_t K[SM2_BYTES];
	uint8_t N[SM2_BYTES];
	uint64_t n[NUM_DIGITS_SM2] = { 0x53BBF40939D54123ull,0x7203DF6B21C6052Bull,0xFFFFFFFFFFFFFFFFull,0xFFFFFFFEFFFFFFFFull };//curve_n
	uint64_t l_tmp[NUM_DIGITS_SM2];
	uint64_t l_s[NUM_DIGITS_SM2];
	uint64_t _1[NUM_DIGITS_SM2] = { 0x1 };
	affpoint p;
	affpoint test;
	int i = 0;
	unsigned l_tries = 0;
	uint64_t k[NUM_DIGITS_SM2] = { 0X6D54B80DEAC1BC21ULL,0XEF3CC1FA3CDBE4CEULL,0X16680F3AD9C02DCCULL,0X59276E27D506861AULL };
	//A3
	do
	{
		//产生随机数k[0,n-1)
		/*
		if (!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(k))
		{
			continue;
		}

		while (bn_cmp(curve_n, k) != 1)
		{
			bn_sub(k, k, curve_n);
		}
		*/

		//A4
		/* tmp = K * G */
		ecc_native2bytes(tmpx, curve_G.x);
		ecc_native2bytes(tmpy, curve_G.y);
		ecc_native2bytes(tmp1, _1);

		ecc_native2bytes(K, k);
		/*
		if (DEBUG) 
		{
			printf("A3:随机数k的值：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", K[i]);
			}
			printf("\n");
			printf("原来点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmpx[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++) 
			{
				printf("%02x ", tmpy[i]);
			}
			printf("\n");
		}
		*/

		//EccPoint_mult(&test, &curve_G, n, NULL); //test=n*G
		
		EccPoint_mult(&p, &curve_G, k, NULL);//p=k*G
		//ecc_native2bytes(tmpx, test.x);
		//ecc_native2bytes(tmpy, test.y);
		ecc_native2bytes(tmp1x, p.x);
		ecc_native2bytes(tmp1y, p.y);
		/*
		if (DEBUG)
		{
			printf("test=n*G点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++) 
			{
				printf("%02x ", tmpx[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++) 
			{
				printf("%02x ", tmpy[i]);
			}
			printf("\n");
			printf("A4:P=K*G点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++) 
			{
				printf("%02x ", tmp1x[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++) 
			{
				printf("%02x ", tmp1y[i]);
			}
			printf("\n");
		}
		*/
		if (bn_isZero(p.x))
			continue;
		if (bn_cmp(curve_n, p.x) != 1)
		{
			bn_sub(p.x, p.x, curve_n);
		}

		//A5
		ecc_bytes2native(l_tmp, p_hash);
		bn_modAdd(p.x, p.x, l_tmp, curve_n); //p.x=p.x+e(hash)-----r
		bn_add(l_tmp, p.x, k);//l_tmp=p.x+k-------r+k
		if (bn_isZero(p.x) || bn_cmp(l_tmp, curve_n) == 0)
			continue;
		/* sign = r */
		ecc_native2bytes(p_sign, p.x);
		/*
		if (DEBUG)
		{
			printf("A5:r=(e+x1)\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", p_sign[i]);
			printf("\n");
		}
		*/
		//A6
		/* s = 1 / (1 + d)*/
		
		ecc_bytes2native(l_tmp, p_sk);//l_tmp=p_sk-------dA
		/*
		if (DEBUG)
		{
			printf("A6:\n");
			printf("dA\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", p_sk[i]);
			printf("\n");
		}
		*/
		bn_modAdd(l_s, _1, l_tmp, curve_n);//l_s=1+dA
		bn_modInv(l_s, l_s, curve_n);//l_s=(1+dA)^-1
		/*
		if (DEBUG)
		{
			ecc_native2bytes(tmp, l_s);
			printf("1/(1+dA)\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", tmp[i]);
			printf("\n");
		}
		*/
		/* k = k - r * d */
		bn_modMult(l_tmp, p.x, l_tmp, curve_n);//l_tmp=p.x*l_tmp--------r*dA
		bn_modSub(k, k, l_tmp, curve_n);//k=k-r*dA

		/* s = s * k */
		bn_modMult(l_s, l_s, k, curve_n);
		
	} while (bn_isZero(l_s));
	//A7
	/* sign = (r, s) */
	ecc_native2bytes(p_sign + SM2_BYTES, l_s);
	/*
	if (DEBUG)
	{
		printf("s=(k-r*dA)/(1+dA)\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", (p_sign+SM2_BYTES)[i]);
		printf("\n");
	}
	*/
	return 1;
}
int sm2_sign_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], uint8_t p_sign[SM2_BYTES * 2])
{
	uint8_t tmp1x[SM2_BYTES], tmp1y[SM2_BYTES], tmp[SM2_BYTES];
	uint8_t tmpx[SM2_BYTES];
	uint8_t tmpy[SM2_BYTES];
	uint8_t tmp1[SM2_BYTES];
	uint8_t K[SM2_BYTES];
	uint8_t N[SM2_BYTES];
	uint64_t n[NUM_DIGITS_SM2] = { 0x53BBF40939D54123ull,0x7203DF6B21C6052Bull,0xFFFFFFFFFFFFFFFFull,0xFFFFFFFEFFFFFFFFull };//curve_n
	uint64_t l_tmp[NUM_DIGITS_SM2];
	uint64_t l_s[NUM_DIGITS_SM2];
	uint64_t _1[NUM_DIGITS_SM2] = { 0x1 };
	affpoint p;
	affpoint test;
	int i = 0;
	unsigned l_tries = 0;
	uint64_t k[NUM_DIGITS_SM2] = { 0X6D54B80DEAC1BC21ULL,0XEF3CC1FA3CDBE4CEULL,0X16680F3AD9C02DCCULL,0X59276E27D506861AULL };
	//A3
	do
	{
		//产生随机数k[0,n-1)
		/*
		if (!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(k))
		{
			continue;
		}

		while (bn_cmp(curve_n, k) != 1)
		{
			bn_sub(k, k, curve_n);
		}
		*/

		//A4
		/* tmp = K * G */
		ecc_native2bytes(tmpx, curve_G.x);
		ecc_native2bytes(tmpy, curve_G.y);
		ecc_native2bytes(tmp1, _1);

		ecc_native2bytes(K, k);
		/*
		if (DEBUG)
		{
			printf("A3:随机数k的值：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", K[i]);
			}
			printf("\n");
			printf("原来点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmpx[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmpy[i]);
			}
			printf("\n");
		}
		*/
		//EccPoint_mult(&test, &curve_G, n, NULL); //test=n*G
		EccPoint_2w_mult(&p, &curve_G, k, NULL);//p=k*G
		//ecc_native2bytes(tmpx, test.x);
		//ecc_native2bytes(tmpy, test.y);
		ecc_native2bytes(tmp1x, p.x);
		ecc_native2bytes(tmp1y, p.y);
		/*
		if (DEBUG)
		{
			
			printf("test=n*G点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmpx[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmpy[i]);
			}
			printf("\n");
			
			printf("A4:P=K*G点的信息：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmp1x[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", tmp1y[i]);
			}
			printf("\n");
		}
		*/
		if (bn_isZero(p.x))
			continue;
		if (bn_cmp(curve_n, p.x) != 1)
		{
			bn_sub(p.x, p.x, curve_n);
		}

		//A5
		ecc_bytes2native(l_tmp, p_hash);
		bn_modAdd(p.x, p.x, l_tmp, curve_n); //p.x=p.x+e(hash)-----r
		bn_add(l_tmp, p.x, k);//l_tmp=p.x+k-------r+k
		if (bn_isZero(p.x) || bn_cmp(l_tmp, curve_n) == 0)
			continue;
		/* sign = r */
		ecc_native2bytes(p_sign, p.x);
		/*
		if (DEBUG)
		{
			printf("A5:r=(e+x1)\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", p_sign[i]);
			printf("\n");
		}
		*/
		//A6
		/* s = 1 / (1 + d)*/
		ecc_bytes2native(l_tmp, p_sk);//l_tmp=p_sk-------dA
		/*
		if (DEBUG)
		{
			printf("A6:\n");
			printf("dA\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", p_sk[i]);
			printf("\n");
		}
		*/
		bn_modAdd(l_s, _1, l_tmp, curve_n);//l_s=1+dA
		bn_modInv(l_s, l_s, curve_n);//l_s=(1+dA)^-1
		/*
		if (DEBUG)
		{
			ecc_native2bytes(tmp, l_s);
			printf("1/(1+dA)\n");
			for (i = 0; i < SM2_BYTES; i++)
				printf("%02x ", tmp[i]);
			printf("\n");
		}
		*/
		/* k = k - r * d */
		bn_modMult(l_tmp, p.x, l_tmp, curve_n);//l_tmp=p.x*l_tmp--------r*dA
		bn_modSub(k, k, l_tmp, curve_n);//k=k-r*dA
		/* s = s * k */
		bn_modMult(l_s, l_s, k, curve_n);
	} while (bn_isZero(l_s));
	//A7
	/* sign = (r, s) */
	ecc_native2bytes(p_sign + SM2_BYTES, l_s);
	/*
	if (DEBUG)
	{
		printf("s=(k-r*dA)/(1+dA)\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", (p_sign + SM2_BYTES)[i]);
		printf("\n");
	}
	*/
	return 1;
}
int sm2_verify(const uint8_t p_publicKey_X[SM2_BYTES], const uint8_t p_publicKey_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_signature[SM2_BYTES * 2])
{
	uint8_t tmp[SM2_BYTES];
	int i = 0;
	uint64_t e[NUM_DIGITS_SM2];
	uint64_t z[NUM_DIGITS_SM2];
	uint64_t R[NUM_DIGITS_SM2];
	affpoint l_public, l_sum;
	uint64_t rx[NUM_DIGITS_SM2];
	uint64_t ry[NUM_DIGITS_SM2];
	uint64_t tx[NUM_DIGITS_SM2];
	uint64_t ty[NUM_DIGITS_SM2];
	uint64_t tz[NUM_DIGITS_SM2];

	uint64_t l_r[NUM_DIGITS_SM2], l_s[NUM_DIGITS_SM2], l_t[NUM_DIGITS_SM2];

	//转换为64bit整数
	ecc_bytes2native(l_public.x, p_publicKey_X);
	ecc_bytes2native(l_public.y, p_publicKey_Y);
	//B1&B2  
	ecc_bytes2native(l_r, p_signature);
	ecc_bytes2native(l_s, p_signature + SM2_BYTES);
	if (bn_isZero(l_r))
	{
		printf("签名值r为0，验证不通过\n");
		return 0;
	}
	if (bn_isZero(l_s))
	{
		printf("签名值s为0，验证不通过\n");
		return 0;
	}
	if (bn_cmp(curve_n, l_r) != 1 )
	{
		printf("签名值r大于n-1，验证不通过\n");
		return 0;
	}
	if (bn_cmp(curve_n, l_s) != 1)
	{
		printf("签名值s大于n-1，验证不通过\n");
		return 0;
	}
	//B5
	/* t = (r + s) mod n */
	bn_modAdd(l_t, l_r, l_s, curve_n);
	if (bn_isZero(l_t))
	{
		printf("签名值r+s为0，验证不通过\n");
		return 0;
	}
	/*
	if (DEBUG)
	{
		ecc_native2bytes(tmp, l_t);
		printf("B5:t=(r'+s')\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	*/
	//B6
	/* Calculate l_sum = G + Q. */
	//sum=PA
	
	bn_set(l_sum.x, l_public.x);
	bn_set(l_sum.y, l_public.y);
	//t=G
	bn_set(tx, curve_G.x);
	bn_set(ty, curve_G.y);
	bn_modSub(z, l_sum.x, tx, curve_p); //z=sum.x-t.x-----PA.x-G.x
	XYCZ_add(tx, ty, l_sum.x, l_sum.y);//sum=sum+t---------PA+G
	bn_modInv(z, z, curve_p);
	AFF2XYCZ(l_sum.x, l_sum.y, z);

	/* Use Shamir's trick to calculate s*G + t*Q */
	affpoint *l_points[4] = { NULL, &curve_G, &l_public, &l_sum };
	unsigned int l_numBits = umax(bn_numBits(l_s), bn_numBits(l_t));

	affpoint *l_point = l_points[(!!bn_testBit(l_s, l_numBits - 1)) | ((!!bn_testBit(l_t, l_numBits - 1)) << 1)];
	bn_set(rx, l_point->x);
	bn_set(ry, l_point->y);
	bn_init0(z);
	z[0] = 1;

	for (i = l_numBits - 2; i >= 0; --i)
	{
		EccPoint_double_jacobian(rx, ry, z);

		int l_index = (!!bn_testBit(l_s, i)) | ((!!bn_testBit(l_t, i)) << 1);
		affpoint *l_point = l_points[l_index];
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
	/*
	if (DEBUG)
	{
		printf("B6:\n");
		printf("sG+tPA\n");
		ecc_native2bytes(tmp, rx);
		printf("x:");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
		ecc_native2bytes(tmp, ry);
		printf("y:");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	*/
	//B7
	/* R = (e + x1) mod n */
	ecc_bytes2native(e, p_hash);
	bn_modAdd(R, e, rx, curve_n);
	/*
	if (DEBUG)
	{
		ecc_native2bytes(tmp,R);
		printf("B7:R=(e+x)\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
		ecc_native2bytes(tmp, l_r);
		printf("r\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	*/
	/* Accept only if R == r. */
	if (!bn_cmp(R, l_r))
		return 1;
	else
	{
		printf("R!=r");
		return 0;
	}
	
}
int sm2_verify_2w(const uint8_t p_publicKey_X[SM2_BYTES], const uint8_t p_publicKey_Y[SM2_BYTES], const uint8_t p_hash[SM2_BYTES], const uint8_t p_signature[SM2_BYTES * 2])
{
	uint8_t tmp[SM2_BYTES];
	int i = 0;
	uint64_t e[NUM_DIGITS_SM2];
	uint64_t z[NUM_DIGITS_SM2];
	uint64_t R[NUM_DIGITS_SM2];
	uint64_t rx[NUM_DIGITS_SM2];
	uint64_t ry[NUM_DIGITS_SM2];
	uint64_t tx[NUM_DIGITS_SM2];
	uint64_t ty[NUM_DIGITS_SM2];
	uint64_t tz[NUM_DIGITS_SM2];
	affpoint l_public, l_sum;

	uint64_t l_r[NUM_DIGITS_SM2], l_s[NUM_DIGITS_SM2], l_t[NUM_DIGITS_SM2];

	//转换为64bit
	ecc_bytes2native(l_public.x, p_publicKey_X);
	ecc_bytes2native(l_public.y, p_publicKey_Y);
	//B1&B2  
	ecc_bytes2native(l_r, p_signature);
	ecc_bytes2native(l_s, p_signature + SM2_BYTES);
	if (bn_isZero(l_r))
	{
		printf("签名值r为0，验证不通过\n");
		return 0;
	}
	if (bn_isZero(l_s))
	{
		printf("签名值s为0，验证不通过\n");
		return 0;
	}
	if (bn_cmp(curve_n, l_r) != 1)
	{
		printf("签名值r大于n-1，验证不通过\n");
		return 0;
	}
	if (bn_cmp(curve_n, l_s) != 1)
	{
		printf("签名值s大于n-1，验证不通过\n");
		return 0;
	}
	//B5
	/* t = (r + s) mod n */
	bn_modAdd(l_t, l_r, l_s, curve_n);
	if (bn_isZero(l_t))
	{
		printf("签名值r+s为0，验证不通过\n");
		return 0;
	}
	/*
	if (DEBUG)
	{
		ecc_native2bytes(tmp, l_t);
		printf("B5:t=(r'+s')\n");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	*/
	//B6
	bn_set(l_sum.x, l_public.x);
	bn_set(l_sum.y, l_public.y);
	//t=G
	bn_set(tx, curve_G.x);
	bn_set(ty, curve_G.y);
	bn_modSub(z, l_sum.x, tx, curve_p); //z=sum.x-t.x-----PA.x-G.x
	XYCZ_add(tx, ty, l_sum.x, l_sum.y);//sum=sum+t---------PA+G
	bn_modInv(z, z, curve_p);
	AFF2XYCZ(l_sum.x, l_sum.y, z);

	// Use Shamir's trick to calculate s*G + t*Q 
	affpoint* l_points[4] = { NULL, &curve_G, &l_public, &l_sum };
	unsigned int l_numBits = umax(bn_numBits(l_s), bn_numBits(l_t));

	affpoint* l_point = l_points[(!!bn_testBit(l_s, l_numBits - 1)) | ((!!bn_testBit(l_t, l_numBits - 1)) << 1)];
	bn_set(rx, l_point->x);
	bn_set(ry, l_point->y);
	bn_init0(z);
	z[0] = 1;
	uint64_t v_tmp1[NLIMB], v_tmp2[NLIMB];
	vec X1Y1[NLIMB / 2], X2Y2[NLIMB / 2];
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
	/*
	if (DEBUG)
	{
		printf("B6:\n");
		printf("sG+tPA\n");
		ecc_native2bytes(tmp, rx);
		printf("x:");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
		ecc_native2bytes(tmp, ry);
		printf("y:");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	*/
	//B7
	/* R = (e + x1) mod n */
	ecc_bytes2native(e, p_hash);
	bn_modAdd(R, e, rx, curve_n);
	
	if (DEBUG)
	{
		ecc_native2bytes(tmp, R);
		printf("  R=");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
		ecc_native2bytes(tmp, l_r);
		printf("  r=");
		for (i = 0; i < SM2_BYTES; i++)
			printf("%02x ", tmp[i]);
		printf("\n");
	}
	
	/* Accept only if R == r. */
	if (!bn_cmp(R, l_r))
		return 1;
	else
	{
		printf("R!=r");
		return 0;
	}

}
int sm2_encrypt(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher)
{
	uint64_t k[NUM_DIGITS_SM2] = {0X6D54B80DEAC1BC21ULL,0XEF3CC1FA3CDBE4CEULL,0X16680F3AD9C02DCC,0X59276E27D506861AULL}, pk_x[NUM_DIGITS_SM2], pk_y[NUM_DIGITS_SM2];
	uint8_t x1[SM2_BYTES], y1[SM2_BYTES], x2[SM2_BYTES], y2[SM2_BYTES], Z[SM2_BYTES * 2], C3[SM3_DIGEST_LENGTH];
	affpoint C1;
	affpoint S;
	unsigned l_tries = 0;
	uint8_t *t;
	int i = 0;

	if (cypher == NULL)
		return 0;
	//A1：产生随机数k[1，n-1]
	do
	{
		/*
		if (!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(k))
		{
			continue;
		}
		while (bn_cmp(curve_n, k) != 1)
		{
			bn_sub(k, k, curve_n);
		}
		*/
		//A2：C1=kG=(x1,y1)
		EccPoint_mult(&C1, &curve_G, k, NULL); 
		ecc_native2bytes(x1, C1.x);
		ecc_native2bytes(y1, C1.y);
		/*
		if (DEBUG)
		{
			printf("A2:C1=k*G：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", x1[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", y1[i]);
			}
			printf("\n");
		}
		*/
		//A3
		ecc_bytes2native(pk_x, p_pk_X);
		ecc_bytes2native(pk_y, p_pk_Y);
		bn_set(S.x, pk_x);
		bn_set(S.y, pk_y);
		
		if (EccPoint_isZero(&S) == 1)
		{
			printf("S为无穷远点\n" );
			return 0;
		}
		//A4: (x2,y2)=kPB
		EccPoint_mult(&S, &S, k, NULL);     
		ecc_native2bytes(x2, S.x);
		ecc_native2bytes(y2, S.y);
		/*
		if (DEBUG)
		{
			printf("A4:k*PB:\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", x2[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", y2[i]);
			}
			printf("\n");
		}
		*/
		//A5: t=KDF(x2||y2, klen)
		memcpy(Z, x2, SM2_BYTES);
		memcpy(Z + SM2_BYTES, y2, SM2_BYTES);
		t = sm2_kdf(Z, mlen);    
		//t = sm2_kdf(Z, 152);
		/*
		if (DEBUG)
		{
			printf("A5:KDF(x2||y2,152):\n");
			for (i = 0; i < mlen; i++)
			{
				printf("%02x ", t[i]);
			}
			printf("\n");
		}
		*/
		if (t == NULL)
			return 0;
	} while (bytes_is_zero(t, mlen) == 1);

	uint8_t *C2 = (uint8_t*)malloc(sizeof(uint8_t) * mlen);
	uint8_t *H = (uint8_t*)malloc(sizeof(uint8_t) * (SM2_BYTES * 2 + mlen));
	//A6  C2=M^t
	for (i = 0; i < mlen; i++)
	{
		C2[i] = t[i] ^ M[i];
	}
	/*
	if (DEBUG)
	{
		printf("M\n");
		for (i = 0; i < mlen; i++)
		{
			printf("%02x ", M[i]);
		}
		printf("\n");
		printf("A6:C2=M^t\n");
		for (i = 0; i < mlen; i++)
		{
			printf("%02x ", C2[i]);
		}
		printf("\n");
	}
	*/
	memcpy(H, x2, SM2_BYTES);
	memcpy(H + SM2_BYTES, M, mlen);
	memcpy(H + SM2_BYTES + mlen, y2, SM2_BYTES);
	//A7    C3=Hash(x2||M||y2)
	sm3_hash(H, C3, SM2_BYTES * 2 + mlen);
	/*
	if (DEBUG)
	{
		printf("A7:C3=Hash(x2||M||y2)\n");
		for (i = 0; i < SM3_DIGEST_LENGTH; i++)
		{
			printf("%02x ", C3[i]);
		}
		printf("\n");
	}
	*/
	//A8
	memcpy(cypher, x1, SM2_BYTES);  
	memcpy(cypher + SM2_BYTES, y1, SM2_BYTES);  //C1长度为SM2_BYTES*2
	memcpy(cypher + SM2_BYTES * 2, C2, mlen);   //C2长度为mlen
	memcpy(cypher + SM2_BYTES * 2 + mlen, C3, SM3_DIGEST_LENGTH);  //C3长度为SM3_DIGEST_LENGTH

	free(C2);
	free(H);
	free(t);
	return 1;
}
int sm2_encrypt_2w(const uint8_t p_pk_X[SM2_BYTES], const uint8_t p_pk_Y[SM2_BYTES], const uint8_t *M, int mlen, uint8_t *cypher)
{
	uint64_t k[NUM_DIGITS_SM2] = { 0X6D54B80DEAC1BC21ULL,0XEF3CC1FA3CDBE4CEULL,0X16680F3AD9C02DCC,0X59276E27D506861AULL }, pk_x[NUM_DIGITS_SM2], pk_y[NUM_DIGITS_SM2];
	uint8_t x1[SM2_BYTES], y1[SM2_BYTES], x2[SM2_BYTES], y2[SM2_BYTES], Z[SM2_BYTES * 2], C3[SM3_DIGEST_LENGTH];
	affpoint C1;
	affpoint S;
	unsigned l_tries = 0;
	uint8_t *t;
	int i = 0;

	if (cypher == NULL)
		return 0;
	//A1：产生随机数k[1，n-1]
	do
	{
		/*
		if (!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
		{
			return 0;
		}
		if (bn_isZero(k))
		{
			continue;
		}
		while (bn_cmp(curve_n, k) != 1)
		{
			bn_sub(k, k, curve_n);
		}
		*/
		//A2：C1=kG=(x1,y1)
		EccPoint_2w_mult(&C1, &curve_G, k, NULL);
		ecc_native2bytes(x1, C1.x);
		ecc_native2bytes(y1, C1.y);
		/*
		if (DEBUG)
		{
			printf("A2:C1=k*G：\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", x1[i]);
			}
			printf("\n");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", y1[i]);
			}
			printf("\n");
		}
		*/
		//A3
		ecc_bytes2native(pk_x, p_pk_X);
		ecc_bytes2native(pk_y, p_pk_Y);
		bn_set(S.x, pk_x);
		bn_set(S.y, pk_y);

		if (EccPoint_isZero(&S) == 1)
		{
			printf("S为无穷远点\n");
			return 0;
		}
		//A4: (x2,y2)=kPB
		EccPoint_2w_mult(&S, &S, k, NULL);
		ecc_native2bytes(x2, S.x);
		ecc_native2bytes(y2, S.y);
		/*
		if (DEBUG)
		{
			printf("  A4:k*PB:\n");
			printf("  ");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", x2[i]);
			}
			printf("\n");
			printf("  ");
			for (i = 0; i < SM2_BYTES; i++)
			{
				printf("%02x ", y2[i]);
			}
			printf("\n");
		}
		*/
		
		//A5: t=KDF(x2||y2, klen)
		memcpy(Z, x2, SM2_BYTES);
		memcpy(Z + SM2_BYTES, y2, SM2_BYTES);
		t = sm2_kdf(Z, mlen);
		//t = sm2_kdf(Z, 152);
		/*
		if (DEBUG)
		{
			printf("  A5:KDF(x2||y2,klen):\n");
			printf("  ");
			for (i = 0; i < mlen; i++)
			{
				printf("%02x ", t[i]);
			}
			printf("\n");
		}
		*/
		if (t == NULL)
			return 0;
	} while (bytes_is_zero(t, mlen) == 1);

	uint8_t *C2 = (uint8_t*)malloc(sizeof(uint8_t) * mlen);
	uint8_t *H = (uint8_t*)malloc(sizeof(uint8_t) * (SM2_BYTES * 2 + mlen));
	//A6  C2=M^t
	for (i = 0; i < mlen; i++)
	{
		C2[i] = t[i] ^ M[i];
	}
	/*
	if (DEBUG)
	{
		printf("M\n");
		for (i = 0; i < mlen; i++)
		{
			printf("%02x ", M[i]);
		}
		printf("\n");
		printf("A6:C2=M^t\n");
		for (i = 0; i < mlen; i++)
		{
			printf("%02x ", C2[i]);
		}
		printf("\n");
	}
	*/
	memcpy(H, x2, SM2_BYTES);
	memcpy(H + SM2_BYTES, M, mlen);
	memcpy(H + SM2_BYTES + mlen, y2, SM2_BYTES);
	//A7    C3=Hash(x2||M||y2)
	sm3_hash(H, C3, SM2_BYTES * 2 + mlen);
	/*
	if (DEBUG)
	{
		printf("A7:C3=Hash(x2||M||y2)\n");
		for (i = 0; i < SM3_DIGEST_LENGTH; i++)
		{
			printf("%02x ", C3[i]);
		}
		printf("\n");
	}
	*/
	//A8
	memcpy(cypher, x1, SM2_BYTES);
	memcpy(cypher + SM2_BYTES, y1, SM2_BYTES);  //C1长度为SM2_BYTES*2
	memcpy(cypher + SM2_BYTES * 2, C2, mlen);   //C2长度为mlen
	memcpy(cypher + SM2_BYTES * 2 + mlen, C3, SM3_DIGEST_LENGTH);  //C3长度为SM3_DIGEST_LENGTH

	free(C2);
	free(H);
	free(t);
	return 1;
}
int sm2_decrypt(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain)
{
	affpoint C1;
	affpoint S;
	uint64_t d[NUM_DIGITS_SM2];
	uint8_t x2[SM2_BYTES], y2[SM2_BYTES], u[SM3_DIGEST_LENGTH], C3[SM3_DIGEST_LENGTH], Z[SM2_BYTES * 2];
	uint8_t *t = NULL,  *C2 = cypher + SM2_BYTES * 2;
	int i = 0;

	if (cypher == NULL)
		return 0;
	/*
	if (DEBUG)
	{
		printf("C1:\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		for (i = SM2_BYTES; i < SM2_BYTES * 2; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		printf("sk:\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", p_sk[i]);
		}
		printf("\n");
	}
	*/
	ecc_bytes2native(C1.x, cypher);
	ecc_bytes2native(C1.y, cypher + SM2_BYTES);
	if (ECC_check_point(&C1) == 0 || EccPoint_isZero(&C1) == 1)
		return 0;
	ecc_bytes2native(d, p_sk);
	//B3
	EccPoint_mult(&S, &C1, d, NULL);//s=d*C1
	ecc_native2bytes(x2, S.x);
	ecc_native2bytes(y2, S.y);
	/*
	if (DEBUG)
	{
		printf("B3:d*C1\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", x2[i]);
		}
		printf("\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", y2[i]);
		}
		printf("\n");
	}
	*/
	memcpy(Z, x2, SM2_BYTES);
	memcpy(Z + SM2_BYTES, y2, SM2_BYTES);
	//B4
	t = sm2_kdf(Z, klen);
	/*
	if (DEBUG)
	{
		printf("t=KDF(x2||y2,klen)\n");
		for (i = 0; i < klen; i++)
		{
			printf("%02x ", t[i]);
		}
		printf("\n");
	}
	*/
	if (t == NULL)
		return 0;
	if (bytes_is_zero(t, klen))
	{
		free(t);
		return 0;
	}
	//B5
	for (i = 0; i < klen; i++)
	{
		plain[i] = C2[i] ^ t[i];
	}
	/*
	if (DEBUG)
	{
		printf("B5: C2^t\n");
		for (i = 0; i < klen; i++)
		{
			printf("%02x ", plain[i]);
		}
		printf("\n");
	}
	*/
	//B6
	uint8_t *H = (uint8_t*)malloc(sizeof(uint8_t)*(SM2_BYTES * 2 + klen));
	memcpy(H, x2, SM2_BYTES);
	memcpy(H + SM2_BYTES, plain, klen);
	memcpy(H + SM2_BYTES + klen, y2, SM2_BYTES);
	sm3_hash(H, u, SM2_BYTES * 2 + klen);
	/*
	if (DEBUG)
	{
		printf("u=Hash(x2||M'||y2)\n");
		for (i = 0; i < SM3_DIGEST_LENGTH; i++)
		{
			printf("%02x ", u[i]);
		}
		printf("\n");
		
	}
	*/
	memcpy(C3, cypher + SM2_BYTES * 2 + klen, SM3_DIGEST_LENGTH);
	for (i = 0; i < SM3_DIGEST_LENGTH; i++)
	{
		if (u[i] != C3[i])
		{
			free(H);
			free(t);
			return 0;
		}

	}
	free(H);
	free(t);
	return 1;
	
}
int sm2_decrypt_2w(const uint8_t p_sk[SM2_BYTES], const uint8_t *cypher, int klen, uint8_t *plain)
{
	affpoint C1;
	affpoint S;
	uint64_t d[NUM_DIGITS_SM2];
	uint8_t x2[SM2_BYTES], y2[SM2_BYTES], u[SM3_DIGEST_LENGTH], C3[SM3_DIGEST_LENGTH], Z[SM2_BYTES * 2];
	uint8_t *t, * C2 = cypher + SM2_BYTES * 2;
	int i = 0;

	if (cypher == NULL)
		return 0;
	/*
	if (DEBUG)
	{
		printf("C1:\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		for (i = SM2_BYTES; i < SM2_BYTES * 2; i++)
		{
			printf("%02x ", cypher[i]);
		}
		printf("\n");
		printf("sk:\n");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", p_sk[i]);
		}
		printf("\n");
	}
	*/
	ecc_bytes2native(C1.x, cypher);
	ecc_bytes2native(C1.y, cypher + SM2_BYTES);
	if (ECC_check_point(&C1) == 0 || EccPoint_isZero(&C1) == 1)
		return 0;
	ecc_bytes2native(d, p_sk);
	//B3
	EccPoint_2w_mult(&S, &C1, d, NULL);//s=d*C1
	ecc_native2bytes(x2, S.x);
	ecc_native2bytes(y2, S.y);
	/*
	if (DEBUG)
	{
		printf("  B3:d*C1\n");
		printf("  ");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", x2[i]);
		}
		printf("\n");
		printf("  ");
		for (i = 0; i < SM2_BYTES; i++)
		{
			printf("%02x ", y2[i]);
		}
		printf("\n");
	}
	*/
	memcpy(Z, x2, SM2_BYTES);
	memcpy(Z + SM2_BYTES, y2, SM2_BYTES);
	//B4
	t = sm2_kdf(Z, klen);
	/*
	if (DEBUG)
	{
		printf("  t=KDF(x2||y2,klen)\n");
		printf("  ");
		for (i = 0; i < klen; i++)
		{
			printf("%02x ", t[i]);
		}
		printf("\n");
	}
	*/
	if (t == NULL)
		return 0;
	if (bytes_is_zero(t, klen))
	{
		free(t);
		return 0;
	}
	//B5
	for (i = 0; i < klen; i++)
	{
		plain[i] = C2[i] ^ t[i];
	}
	/*
	if (DEBUG)
	{
		printf("  B5: M'=C2^t\n");
		printf("  ");
		for (i = 0; i < klen; i++)
		{
			printf("%02x ", plain[i]);
		}
		printf("\n");
	}
	*/
	//B6
	uint8_t *H = (uint8_t*)malloc(sizeof(uint8_t)*(SM2_BYTES * 2 + klen));
	memcpy(H, x2, SM2_BYTES);
	memcpy(H + SM2_BYTES, plain, klen);
	memcpy(H + SM2_BYTES + klen, y2, SM2_BYTES);
	sm3_hash(H, u, SM2_BYTES * 2 + klen);
	/*
	if (DEBUG)
	{
		printf("  u=Hash(x2||M'||y2)\n");
		printf("  ");
		for (i = 0; i < SM3_DIGEST_LENGTH; i++)
		{
			printf("%02x ", u[i]);
		}
		printf("\n");
	}
	*/
	memcpy(C3, cypher + SM2_BYTES * 2 + klen, SM3_DIGEST_LENGTH);
	for (i = 0; i < SM3_DIGEST_LENGTH; i++)
	{
		if (u[i] != C3[i])
		{
			free(H);
			free(t);
			return 0;
		}

	}
	free(H);
	free(t);
	return 1;

}
unsigned char* sm2_kdf(unsigned char Z[SM2_BYTES * 2], int klen)
{
	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001;
	int i, m, n;
	unsigned char* p;
	unsigned char* K = (unsigned char*)malloc(klen * (sizeof(unsigned char)));
	memcpy(buf, Z, SM2_BYTES*2);                   //把x2，y2传入buf

	m = klen / 32;
	n = klen % 32;
	p = K;

	for (i = 0; i < m; i++)       //buf 64-70
	{
		buf[64] = (ct >> 24) & 0xFF;   //ct前8位
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3_hash(buf, p, 68);                       //sm3后结果放在p中
		p += 32;
		ct++;
	}

	if (n != 0)
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3_hash(buf, digest, 68);
	}

	memcpy(p, digest, n);

	for (i = 0; i < klen; i++)
	{
		if (K[i] != 0)      //kbuf中有i+1个0
			break;
	}

	return K;
}
void print_sk(uint8_t p_sk[SM2_BYTES])
{
	printf(" -Private Key\n");
	printf("  ");
	int i;
	for (i = 0; i <SM2_BYTES-1; i++)
	{
		printf("%02x ",p_sk[i]);
		if (i == SM2_BYTES / 2 - 1)
		{
			printf("\n");
			printf("  ");
		}
	}
	printf("%02x\n", p_sk[SM2_BYTES-1]);
}
void print_affpoint(uint8_t p_pk_X[SM2_BYTES], uint8_t p_pk_Y[SM2_BYTES])
{
	int i;
	printf(" -X:\n");
	printf("  ");
	for (i = 0; i < SM2_BYTES - 1; i++)
	{
		printf("%02x ", p_pk_X[i]);
		if (i == SM2_BYTES / 2 - 1)
		{
			printf("\n");
			printf("  ");
		}
	}
	printf("%02x\n", p_pk_X[SM2_BYTES - 1]);
	printf(" -Y:\n");
	printf("  ");
	for (i = 0; i < SM2_BYTES - 1; i++)
	{
		printf("%02x ", p_pk_Y[i]);
		if (i == SM2_BYTES / 2 - 1)
		{
			printf("\n");
			printf("  ");
		}
	}
	printf("%02x\n", p_pk_Y[SM2_BYTES - 1]);
}
void print_sign(uint8_t p_sign[SM2_BYTES*2])
{
	printf(" -Signature(byte):\n");
	int i;
	printf("  r=");
	for (i = 0; i < SM2_BYTES*2 - 1;i++)
	{
		if (i == SM2_BYTES)
		{
			printf("\n");
			printf("  s=");
		}
		printf("%02x ", p_sign[i]);
	}
	printf("%02x\n", p_sign[SM2_BYTES*2 - 1]);
}
#include"pfd.h"
#define EVEN(bn) !(bn[0]&1)  //bn为偶数，EVEN(bn)为1
#define DEBUG 1
#define MASK13 0X1000

extern uint64_t curve_p[NUM_DIGITS_SM2];
extern uint64_t curve_b[NUM_DIGITS_SM2];
extern uint64_t curve_a[NUM_DIGITS_SM2];
extern affpoint curve_G;
extern uint64_t curve_n[NUM_DIGITS_SM2];
vec vec_pp[NLIMB / 2];

int bytes_is_zero(const uint8_t *input, int len)
{
	int i = 0;

	for (i = 0; i < len; i++)
	{
		if (input[i] != 0)
			return 0;
	}

	return 1;
}
 int bn_isZero(uint64_t *p_bn)
{
	int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
	{
		if (p_bn[i])
			return 0;
	}
	return 1;
}
 void bn_init0(uint64_t *p_bn)
{
	int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
		p_bn[i] = 0;
}
 void bn_set(uint64_t *p_dest, uint64_t *p_src)
{
	int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
	{
		p_dest[i] = p_src[i];
	}
}
 void bn_rshift1(uint64_t *p_bn)
{
	uint64_t *l_end = p_bn;
	uint64_t l_carry = 0;

	p_bn += NUM_DIGITS_SM2;
	while (p_bn-- > l_end)
	{

		uint64_t l_temp = *p_bn;
		*p_bn = (l_temp >> 1) | l_carry;
		l_carry = l_temp << 63;
	}
}
 uint64_t bn_lshift(uint64_t *p_result, uint64_t *p_in, unsigned int p_shift)
{
	uint64_t l_carry = 0;
	unsigned int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
	{
		uint64_t l_temp = p_in[i];
		p_result[i] = (l_temp << p_shift) | l_carry;
		l_carry = l_temp >> (64 - p_shift);
	}
	return l_carry;
}
 uint64_t bn_testBit(uint64_t *p_bn, int p_bit)
{
	return (p_bn[p_bit / 64] & ((uint64_t)1 << (p_bit % 64)));
}
 unsigned int numBits(uint64_t num)
 {
	 int i;
	 for (i = 0; num; i++)
		 num >>= 1;
 }
 unsigned int bn_numBits(uint64_t *p_bn)
{
	unsigned int i;
	uint64_t l_digit;

	unsigned int l_numDigits = bn_numDigits(p_bn);
	if (l_numDigits == 0)
	{
		return 0;
	}

	l_digit = p_bn[l_numDigits - 1];
	for (i = 0; l_digit; ++i)
	{
		l_digit >>= 1;
	}

	return ((l_numDigits - 1) * 64 + i);
}
 unsigned int bn_numDigits(uint64_t *p_bn)
{
	int i;
	/* Search from the end until we find a non-zero digit.
	   We do it in reverse because we expect that most digits will be nonzero. */
	for (i = NUM_DIGITS_SM2 - 1; i >= 0 && p_bn[i] == 0; --i);

	return (i + 1);
}
 uint64_t bn_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
	uint64_t l_carry = 0;
	int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
	{
		uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
		if (l_sum != p_left[i])
		{
			l_carry = (l_sum < p_left[i]);
		}
		p_result[i] = l_sum;
	}
	return l_carry;
}
 uint64_t bn_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
	int64_t l_borrow = 0;
	int i;
	for (i = 0; i < NUM_DIGITS_SM2; i++)
	{
		uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
		if (l_diff != p_left[i])
		{
			l_borrow = (l_diff > p_left[i]);
		}
		p_result[i] = l_diff;
	}
	return l_borrow;
}
 void mod_sqrt(uint64_t a[NUM_DIGITS_SM2])
{
	unsigned i;
	uint64_t p1[NUM_DIGITS_SM2] = { 1 };
	uint64_t l_result[NUM_DIGITS_SM2] = { 1 };

	/* Since curve_p == 3 (mod 4) for all supported curves, we can
	   compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
	bn_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
	for (i = bn_numBits(p1) - 1; i > 1; --i)
	{
		bn_modSquare_fast(l_result, l_result);
		if (bn_testBit(p1, i))
		{
			bn_modMult_fast(l_result, l_result, a);
		}
	}
	bn_set(a, l_result);
}
 int bn_cmp(uint64_t *p_left, uint64_t *p_right)
{
	int i;
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; --i)
	{
		if (p_left[i] > p_right[i])
		{
			return 1;
		}
		else if (p_left[i] < p_right[i])
		{
			return -1;
		}
	}
	return 0;
}
 void bn_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
	uint64_t l_carry = bn_add(p_result, p_left, p_right);
	if (l_carry || bn_cmp(p_result, p_mod) >= 0)
	{ /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
		bn_sub(p_result, p_result, p_mod);
	}
}
 void bn_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
	uint64_t l_borrow = bn_sub(p_result, p_left, p_right);
	if (l_borrow)
	{ /* In this case, p_result == -diff == (max int) - diff.
		 Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
		bn_add(p_result, p_result, p_mod);
	}
} 
 void bn_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
	uint64_t l_tmp[NUM_DIGITS_SM2];
	int l_carry;

	/* s1 */
	bn_set(p_result, p_product);

	/* s2 */
	l_tmp[0] = p_product[6];
	l_tmp[1] = p_product[4] << 32;
	l_tmp[2] = p_product[4] >> 32 | p_product[5] << 32;
	l_tmp[3] = p_product[5] >> 32 | p_product[4] << 32;
	l_carry = bn_add(p_result, p_result, l_tmp);

	/* s3 */
	l_tmp[0] = p_product[4];
	l_tmp[1] = p_product[7] & 0xffffffff00000000ull;
	l_tmp[2] = 0;
	l_tmp[3] = p_product[4] & 0xffffffff00000000ull;
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s4 */
	l_tmp[0] = p_product[5] << 32 | p_product[4] >> 32;
	l_tmp[1] = p_product[7] << 32;
	l_tmp[2] = p_product[7] >> 32;
	l_tmp[3] = p_product[5] << 32;
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s5 */
	l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32);
	l_tmp[1] = p_product[5] & 0xffffffff00000000ull;
	l_tmp[2] = p_product[6];
	l_tmp[3] = p_product[7];
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s6 */
	l_tmp[0] = p_product[5];
	l_tmp[1] = p_product[6] << 32;
	l_tmp[2] = p_product[6] >> 32 | p_product[7] << 32;
	l_tmp[3] = p_product[7] >> 32 | (p_product[5] & 0xffffffff00000000ull);
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s7 */
	l_tmp[0] = 0;
	l_tmp[1] = 0;
	l_tmp[2] = 0;
	l_tmp[3] = p_product[6] << 32;
	l_carry += bn_lshift(l_tmp, l_tmp, 1);
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s8 */
	l_tmp[0] = p_product[6] >> 32;
	l_tmp[1] = 0;
	l_tmp[2] = 0;
	l_tmp[3] = p_product[6] & 0xffffffff00000000ull;
	l_carry += bn_lshift(l_tmp, l_tmp, 1);
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s9 */
	l_tmp[0] = p_product[7] << 32 | (p_product[7] & 0xffffffff);
	l_tmp[1] = 0;
	l_tmp[2] = 0;
	l_tmp[3] = p_product[7] << 32;
	l_carry += bn_lshift(l_tmp, l_tmp, 1);
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s10 */
	l_tmp[0] = p_product[7] >> 32 | (p_product[7] & 0xffffffff00000000ull);
	l_tmp[1] = p_product[6] & 0xffffffff00000000ull;
	l_tmp[2] = p_product[7];
	l_tmp[3] = p_product[7] & 0xffffffff00000000ull;
	l_carry += bn_lshift(l_tmp, l_tmp, 1);
	l_carry += bn_add(p_result, p_result, l_tmp);

	/* s11 */
	l_tmp[0] = 0;
	l_tmp[1] = (p_product[4] & 0xffffffff);
	l_tmp[2] = 0;
	l_tmp[3] = 0;
	l_carry -= bn_sub(p_result, p_result, l_tmp);

	/* s12 */
	l_tmp[0] = 0;
	l_tmp[1] = p_product[4] >> 32;
	l_tmp[2] = 0;
	l_tmp[3] = 0;
	l_carry -= bn_sub(p_result, p_result, l_tmp);

	/* s13 */
	l_tmp[0] = 0;
	l_tmp[1] = p_product[6] >> 32;
	l_tmp[2] = 0;
	l_tmp[3] = 0;
	l_carry -= bn_sub(p_result, p_result, l_tmp);

	/* s14 */
	l_tmp[0] = 0;
	l_tmp[1] = p_product[7] & 0xffffffff;
	l_tmp[2] = 0;
	l_tmp[3] = 0;
	l_carry -= bn_sub(p_result, p_result, l_tmp);

	if (l_carry < 0)
	{
		do
		{
			l_carry += bn_add(p_result, p_result, curve_p);
		} while (l_carry < 0);
	}
	else
	{
		while (l_carry || bn_cmp(curve_p, p_result) != 1)
		{
			l_carry -= bn_sub(p_result, p_result, curve_p);
		}
	}
}
 void bn_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
	if (FAST_MODE) 
	{
		//先乘再模
		uint64_t l_product[2 * NUM_DIGITS_SM2];
		bn_mult(l_product, p_left, p_right);   //支持uint128_t的运算方式不同  
		bn_mmod_fast(p_result, l_product);
	}
	else 
	{
		bn_modMult(p_result, p_left, p_right, curve_p);
	}
}
 void bn_modSquare_fast(uint64_t *p_result, uint64_t *p_left)
{
	if (FAST_MODE) 
	{
		uint64_t l_product[2 * NUM_DIGITS_SM2];
		bn_square(l_product, p_left);
		bn_mmod_fast(p_result, l_product);
	}
	else 
	{
		bn_modMult(p_result, p_left, p_left, curve_p);
	}
}
 void bn_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
	uint64_t l_product[2 * NUM_DIGITS_SM2];
	uint64_t l_modMultiple[2 * NUM_DIGITS_SM2];
	unsigned int l_digitShift, l_bitShift;
	unsigned int l_productBits;
	unsigned int l_modBits = bn_numBits(p_mod);

	bn_mult(l_product, p_left, p_right);
	l_productBits = bn_numBits(l_product + NUM_DIGITS_SM2);
	if (l_productBits)
	{
		l_productBits += NUM_DIGITS_SM2 * 64;
	}
	else
	{
		l_productBits = bn_numBits(l_product);
	}

	if (l_productBits < l_modBits)
	{ /* l_product < p_mod. */
		bn_set(p_result, l_product);
		return;
	}

	/* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
	   power of two possible while still resulting in a number less than p_left. */
	bn_init0(l_modMultiple);
	bn_init0(l_modMultiple + NUM_DIGITS_SM2);
	l_digitShift = (l_productBits - l_modBits) / 64;
	l_bitShift = (l_productBits - l_modBits) % 64;
	if (l_bitShift)
	{
		l_modMultiple[l_digitShift + NUM_DIGITS_SM2] = bn_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift);
	}
	else
	{
		bn_set(l_modMultiple + l_digitShift, p_mod);
	}

	/* Subtract all multiples of p_mod to get the remainder. */
	bn_init0(p_result);
	p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
	while (l_productBits > NUM_DIGITS_SM2 * 64 || bn_cmp(l_modMultiple, p_mod) >= 0)
	{
		int l_cmp = bn_cmp(l_modMultiple + NUM_DIGITS_SM2, l_product + NUM_DIGITS_SM2);
		if (l_cmp < 0 || (l_cmp == 0 && bn_cmp(l_modMultiple, l_product) <= 0))
		{
			if (bn_sub(l_product, l_product, l_modMultiple))
			{ /* borrow */
				bn_sub(l_product + NUM_DIGITS_SM2, l_product + NUM_DIGITS_SM2, p_result);
			}
			bn_sub(l_product + NUM_DIGITS_SM2, l_product + NUM_DIGITS_SM2, l_modMultiple + NUM_DIGITS_SM2);
		}
		uint64_t l_carry = (l_modMultiple[NUM_DIGITS_SM2] & 0x01) << 63;
		bn_rshift1(l_modMultiple + NUM_DIGITS_SM2);
		bn_rshift1(l_modMultiple);
		l_modMultiple[NUM_DIGITS_SM2 - 1] |= l_carry;

		l_productBits--;
	}
	bn_set(p_result, l_product);
}
 void bn_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod)
{
	uint64_t a[NUM_DIGITS_SM2], b[NUM_DIGITS_SM2], u[NUM_DIGITS_SM2], v[NUM_DIGITS_SM2];
	uint64_t l_carry;
	int l_cmpResult;

	if (bn_isZero(p_input))
	{
		bn_init0(p_result);
		return;
	}

	bn_set(a, p_input);
	bn_set(b, p_mod);
	bn_init0(u);
	u[0] = 1;
	bn_init0(v);

	while ((l_cmpResult = bn_cmp(a, b)) != 0)
	{
		l_carry = 0;
		//a为偶数
		if (EVEN(a))
		{
			bn_rshift1(a);
			if (!EVEN(u))
			{
				l_carry = bn_add(u, u, p_mod);
			}
			bn_rshift1(u);
			if (l_carry)
			{
				u[NUM_DIGITS_SM2 - 1] |= 0x8000000000000000ull;
			}
		}
		//b为偶数
		else if (EVEN(b))
		{
			bn_rshift1(b);
			if (!EVEN(v))
			{
				l_carry = bn_add(v, v, p_mod);
			}
			bn_rshift1(v);
			if (l_carry)
			{
				v[NUM_DIGITS_SM2 - 1] |= 0x8000000000000000ull;
			}
		}
		//a>b
		else if (l_cmpResult > 0)
		{
			bn_sub(a, a, b);
			bn_rshift1(a);
			if (bn_cmp(u, v) < 0)
			{
				bn_add(u, u, p_mod);
			}
			bn_sub(u, u, v);
			if (!EVEN(u))
			{
				l_carry = bn_add(u, u, p_mod);
			}
			bn_rshift1(u);
			if (l_carry)
			{
				u[NUM_DIGITS_SM2 - 1] |= 0x8000000000000000ull;
			}
		}
		else
		{
			bn_sub(b, b, a);
			bn_rshift1(b);
			if (bn_cmp(v, u) < 0)
			{
				bn_add(v, v, p_mod);
			}
			bn_sub(v, v, u);
			if (!EVEN(v))
			{
				l_carry = bn_add(v, v, p_mod);
			}
			bn_rshift1(v);
			if (l_carry)
			{
				v[NUM_DIGITS_SM2 - 1] |= 0x8000000000000000ull;
			}
		}
	}

	bn_set(p_result, u);
}
 void bn_modinv_addchain(uint64_t *p_result,uint64_t *p_input)
 {
	 int i;
	 uint64_t z3[NUM_DIGITS_SM2], z15[NUM_DIGITS_SM2],tmp[NUM_DIGITS_SM2];;
	 //z=p_input  t=p_result
	 //z3=z^2  *  z  1S+1M
	 bn_modSquare_fast(tmp,p_input);//tmp=z^2
	 bn_modMult_fast(z3,tmp, p_input); //z3=z^2*z

	 //z15=z3^2^2*z3  2S+1M
	 bn_modSquare_fast(tmp, z3);//tmp=z3^2
	 bn_modSquare_fast(tmp, tmp);//tmp=z3^2^2
	 bn_modMult_fast(z15, tmp, z3);//z15

	 //t0=z15^2^2*z3  2S+1M
	 uint64_t t0[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, z15);//tmp=z15^2
	 bn_modSquare_fast(tmp, tmp);//tmp=z15^2^2
	 bn_modMult_fast(t0, tmp, z3);

	 //t1=(t0)^2^6*t0  6S+1M
	 uint64_t t1[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, t0);//tmp=t0^2
	 for (i = 0; i < 5; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);
	 }
	 bn_modMult_fast(t1, tmp, t0);

	 //t2=(((t1)^2^12*t1)^2^6)*t0  18S+2M
	 uint64_t t2[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, t1);//tmp=t1^2
	 for (i = 0; i < 11; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);
	 }
	 bn_modMult_fast(tmp, tmp, t1);//tmp=(t1)^2^12*t1
	 for (i = 0; i < 6; i++)
	 {
		 bn_modSquare_fast(tmp, tmp); //((t1)^2^12*t1)^2^6
	 }
	 bn_modMult_fast(t2, tmp, t0);

	 //t3=t2^2*z  1S+1M
	 uint64_t t3[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, t2);
	 bn_modMult_fast(t3, tmp, p_input);

	 //t4=((((t3)^2^32*t3)^2^31*t3)^2^31*t3)^2^31*t3  125S+4M
	 uint64_t t4[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, t3);
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp); //tmp=(t3)^2^32
	 }
	 bn_modMult_fast(tmp, tmp, t3);
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);//tmp=((t3)^2^32*t3)^2^31
	 }
	 bn_modMult_fast(tmp, tmp, t3);//tmp=((t3)^2^32*t3)^2^31*t3
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);//tmp=(((t3)^2^32*t3)^2^31*t3)^2^31
	 }
	 bn_modMult_fast(tmp, tmp, t3);//tmp=(((t3)^2^32*t3)^2^31*t3)^2^31*t3
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);//tmp=((((t3)^2^32*t3)^2^31*t3)^2^31*t3)^2^31
	 }
	 bn_modMult_fast(t4, tmp, t3);

	 //t5=((t4)^2^4*z15)^2^32  36S+1M
	 uint64_t t5[NUM_DIGITS_SM2];
	 bn_modSquare_fast(tmp, t4);
	 for (i = 0; i < 3; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);//tmp=(t4)^2^4
	 }
	 bn_modMult_fast(tmp, tmp, z15);
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);
	 }
	 bn_modSquare_fast(t5, tmp);

	 //t=(((t5)^2^31*t3)^2^31*t3)^2^2*z  64S+3M
	 bn_modSquare_fast(tmp, t5);
	 for (i = 0; i < 30; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);
	 }
	 bn_modMult_fast(tmp, tmp, t3);//tmp=(t5)^2^31*t3
	 for (i = 0; i < 31; i++)
	 {
		 bn_modSquare_fast(tmp, tmp);//tmp=((t5)^2^31*t3)^2^31
	 }
	 bn_modMult_fast(tmp, tmp, t3);
	 bn_modSquare_fast(tmp, tmp);
	 bn_modSquare_fast(tmp, tmp);
	 bn_modMult_fast(p_result, tmp, p_input);//最终结果
 }
 unsigned int umax(unsigned int a, unsigned int b)
 {
	 return (a > b ? a : b);
 }
#if SUPPORTS_INT128   //直接使用uint128进行乘法运算（64*64->128）

 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
	uint128_t r01 = 0;
	uint64_t r2 = 0;

	unsigned int i, k;

	/* Compute each digit of p_result in sequence, maintaining the carries. */
	for (k = 0; k < NUM_DIGITS_SM2 * 2 - 1; ++k)
	{
		unsigned int l_min = (k < NUM_DIGITS_SM2 ? 0 : (k + 1) - NUM_DIGITS_SM2);
		for (i = l_min; i <= k && i < NUM_DIGITS_SM2; ++i)
		{
			uint128_t l_product = (uint128_t)p_left[i] * p_right[k - i];
			r01 += l_product;
			r2 += (r01 < l_product);
		}
		p_result[k] = (uint64_t)r01;
		r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
		r2 = 0;
	}

	p_result[NUM_DIGITS_SM2 * 2 - 1] = (uint64_t)r01;
}

/* Computes p_result = p_left^2. */
 void bn_square(uint64_t *p_result, uint64_t *p_left)
{
	uint128_t r01 = 0;
	uint64_t r2 = 0;

	uint i, k;
	for (k = 0; k < NUM_DIGITS_SM2 * 2 - 1; ++k)
	{
		uint l_min = (k < NUM_DIGITS_SM2 ? 0 : (k + 1) - NUM_DIGITS_SM2);
		for (i = l_min; i <= k && i <= k - i; ++i)
		{
			uint128_t l_product = (uint128_t)p_left[i] * p_left[k - i];
			if (i < k - i)
			{
				r2 += l_product >> 127;
				l_product *= 2;
			}
			r01 += l_product;
			r2 += (r01 < l_product);
		}
		p_result[k] = (uint64_t)r01;
		r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
		r2 = 0;
	}

	p_result[NUM_DIGITS_SM2 * 2 - 1] = (uint64_t)r01;
}

#else 

 uint128_t mul_64_64(uint64_t p_left, uint64_t p_right)
{
	uint128_t l_result;

	uint64_t a0 = p_left & 0xffffffffull;
	uint64_t a1 = p_left >> 32;
	uint64_t b0 = p_right & 0xffffffffull;
	uint64_t b1 = p_right >> 32;

	uint64_t m0 = a0 * b0;
	uint64_t m1 = a0 * b1;
	uint64_t m2 = a1 * b0;
	uint64_t m3 = a1 * b1;

	m2 += (m0 >> 32);
	m2 += m1;
	if (m2 < m1)
	{ // overflow
		m3 += 0x100000000ull;
	}

	l_result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
	l_result.m_high = m3 + (m2 >> 32);

	return l_result;
}

 uint128_t add_128_128(uint128_t a, uint128_t b)
{
	uint128_t l_result;
	l_result.m_low = a.m_low + b.m_low;
	l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
	return l_result;
}

 void bn_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
	uint128_t r01 = { 0, 0 };
	//进位
	uint64_t r2 = 0;
	unsigned int i, k;

	/* Compute each digit of p_result in sequence, maintaining the carries. */
	for (k = 0; k < NUM_DIGITS_SM2 * 2 - 1; k++)
	{
		unsigned int l_min = (k < NUM_DIGITS_SM2 ? 0 : (k + 1) - NUM_DIGITS_SM2);
		for (i = l_min; i <= k && i < NUM_DIGITS_SM2; i++)
		{
			uint128_t l_product = mul_64_64(p_left[i], p_right[k - i]);
			r01 = add_128_128(r01, l_product);
			r2 += (r01.m_high < l_product.m_high);
		}
		p_result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}
	p_result[NUM_DIGITS_SM2 * 2 - 1] = r01.m_low;
}

 void bn_square(uint64_t *p_result, uint64_t *p_left)
{
	uint128_t r01 = { 0, 0 };
	uint64_t r2 = 0;

	unsigned int i, k;
	for (k = 0; k < NUM_DIGITS_SM2 * 2 - 1; ++k)
	{
		unsigned int l_min = (k < NUM_DIGITS_SM2 ? 0 : (k + 1) - NUM_DIGITS_SM2);
		for (i = l_min; i <= k && i <= k - i; ++i)
		{
			uint128_t l_product = mul_64_64(p_left[i], p_left[k - i]);
			if (i < k - i)
			{
				r2 += l_product.m_high >> 63;
				l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >> 63);
				l_product.m_low <<= 1;
			}
			r01 = add_128_128(r01, l_product);
			r2 += (r01.m_high < l_product.m_high);
		}
		p_result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}

	p_result[NUM_DIGITS_SM2 * 2 - 1] = r01.m_low;
}
#endif

 void get_channel(uint64_t r[NLIMB], const vec z[NLIMB / 2], const int ch0,const int ch1)
 {
	 int i;
	 for (i = 0; i < NLIMB/2; i++)
	 {
		 r[2 * i] = ((uint64_t*)&z[i])[ch0];
		 r[2 * i+1] = ((uint64_t*)&z[i])[ch1];
	 }
 }
 void radix64to26(uint64_t v[NLIMB], uint64_t a[NUM_DIGITS_SM2]) {
	 //26
	 v[0] = a[0]&0x0000000003ffffff; 
	 //26
	 v[1] = (a[0]>>26)& 0x0000000003ffffff;
	 //26
	 v[2] = (a[0] >> 52);
	 v[2]|=(a[1] & 0x0000000000003fff) << 12;
	 //26
	 v[3] = (a[1]>>14)& 0x0000000003ffffff;
	 //26
	 v[4] = (a[1] >> 40);
	 v[4] |= (a[2] & 0x0000000000000003) << 24;

	 //26
	 v[5] = (a[2]>>2) & 0x0000000003ffffff;
	 //26
	 v[6] = (a[2]>>28) & 0x0000000003ffffff;
	 //26
	 v[7] = (a[2] >> 54);
	 v[7]|= (a[3] & 0x000000000000ffff) << 10;
	 //26
	 v[8] = (a[3]>>16) & 0x0000000003ffffff;
	 //22
	 v[9] = a[3]>>42 ;
 }
 void vecto64(uint64_t x[NUM_DIGITS_SM2], uint64_t y[NUM_DIGITS_SM2], vec z[NLIMB / 2])
 {
	 //AVX2寄存器到[NUM_DIGITS_SM2]长度素域元素的映射  分为两步
	 //1.寄存器元素映射到两个长为NLIMB数组
	 uint64_t a[NLIMB], b[NLIMB], r[NUM_DIGITS_SM2 * 2] = { 0 };
	 int i = 0;
	 get_channel(a, z, 2, 3);
	 get_channel(b, z, 0, 1);
	 //2.两个vec数组转换为长度为[NUM_DIGITS*2]radix64数组
	 int sum = 0;
	 r[sum / 64] = a[0] & MASK26;
	 sum += 26;
	 a[1] += a[0] >> 26;
	 r[sum / 64] |= (a[1] & MASK26) << 26;
	 sum += 26;
	 a[2] += a[1] >> 26;
	 r[sum / 64] |= (a[2] & 0xfff) << 52;
	 sum += 12;
	 r[sum / 64] = (a[2] >> 12) & 0x3fff;
	 sum += 14;
	 a[3] += a[2] >> 26;
	 r[sum / 64] |= (a[3] & MASK26) << 14;
	 sum += 26;
	 a[4] += a[3] >> 26;
	 r[sum / 64] |= (a[4] & 0xffffff) << 40;
	 sum += 24;
	 r[sum / 64] = (a[4] >> 24) & 0x3;
	 sum += 2;
	 a[5] += a[4] >> 26;
	 r[sum / 64] |= (a[5] & MASK26) << 2;
	 sum += 26;
	 a[6] += a[5] >> 26;
	 r[sum / 64] |= (a[6] & MASK26) << 28;
	 sum += 26;
	 a[7] += a[6] >> 26;
	 r[sum / 64] |= (a[7] & 0x3ff) << 54;
	 sum += 10;
	 r[sum / 64] = (a[7] >> 10) & 0xffff;
	 sum += 16;
	 a[8] += a[7] >> 26;
	 r[sum / 64] |= (a[8] & MASK26) << 16;
	 sum += 26;
	 a[9] += a[8] >> 26;
	 r[sum / 64] |= (a[9] & 0x3fffff) << 42;
	 //sum += numBits(a[9] & 0x3fffff);
	 uint64_t rest = a[9] >> 22; //剩余不超过64bit
	 unsigned int num;
	 if (rest == 0)
	 {
		 num = 0;
		 sum += numBits(a[9] & 0x3fffff);
	 }

	 else
	 {
		 num = numBits(rest);
		 sum += 22;
	 }
	 sum += num;
	 if (sum < 256)
	 {
		 for (i = 0; i < NUM_DIGITS_SM2; i++)
		 {
			 x[i] = r[i];
		 }
	 }
	 else
	 {
		 r[4] = rest;
		 bn_mmod_fast(x, r);
	 }

	 sum = 0;
	 r[sum / 64] = b[0] & MASK26;
	 sum += 26;
	 b[1] += b[0] >> 26;
	 r[sum / 64] |= (b[1] & MASK26) << 26;
	 sum += 26;
	 b[2] += b[1] >> 26;
	 r[sum / 64] |= (b[2] & 0xfff) << 52;
	 sum += 12;
	 r[sum / 64] = (b[2] >> 12) & 0x3fff;
	 sum += 14;
	 b[3] += b[2] >> 26;
	 r[sum / 64] |= (b[3] & MASK26) << 14;
	 sum += 26;
	 b[4] += b[3] >> 26;
	 r[sum / 64] |= (b[4] & 0xffffff) << 40;
	 sum += 24;
	 r[sum / 64] = (b[4] >> 24) & 0x3;
	 sum += 2;
	 b[5] += b[4] >> 26;
	 r[sum / 64] |= (b[5] & MASK26) << 2;
	 sum += 26;
	 b[6] += b[5] >> 26;
	 r[sum / 64] |= (b[6] & MASK26) << 28;
	 sum += 26;
	 b[7] += b[6] >> 26;
	 r[sum / 64] |= (b[7] & 0x3ff) << 54;
	 sum += 10;
	 r[sum / 64] = (b[7] >> 10) & 0xffff;
	 sum += 16;
	 b[8] += b[7] >> 26;
	 r[sum / 64] |= (b[8] & MASK26) << 16;
	 sum += 26;
	 b[9] += b[8] >> 26;
	 r[sum / 64] |= (b[9] & 0x3fffff) << 42;
	 //sum += numBits(b[9] & 0x3fffff);
	 rest = b[9] >> 22;
	 if (rest == 0)
	 {
		 num = 0;
		 sum += numBits(b[9] & 0x3fffff);
	 }

	 else
	 {
		 num = numBits(rest);
		 sum += 22;
	 }
	 sum += num;
	 if (sum < 256)
	 {
		 for (i = 0; i < NUM_DIGITS_SM2; i++)
		 {
			 y[i] = r[i];
		 }
	 }
	 else
	 {
		 r[4] = rest;
		 bn_mmod_fast(y, r);
	 }


 }
 void set_vector(vec z[NLIMB / 2], const uint64_t x[NLIMB],const uint64_t y[NLIMB])
 {
	 int i;
	 for (i = 0; i < NLIMB/2; i++)
	 {
		 z[i]=VSET64(x[2 * i + 1], x[2 * i], y[2 * i + 1], y[2 * i]); 
	 }
 }
 void set_prime(vec z[NLIMB / 2], const uint64_t x[NLIMB])
 {
	 int i;
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 z[i]=VSET64(x[2 * i + 1], x[2 * i], x[2 * i + 1], x[2 * i]);
	 }
 }
 int test_limbsign(vec *r)
 {
	 int i;
	 long long int* lo;
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 lo = (long long int*) &r[i];
		 if (lo[0] >= 0 && lo[1] >= 0 && lo[2] >= 0 && lo[3] >= 0)
			 continue;
		 else
			 return 0;//存在为负数的limbs
	 }
	 return 1;
 }

 void vec_2w_sub(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2])
 {
	 int i = 0, flag[4] = { 0 };
	 uint64_t arry_p[NLIMB];
	 radix64to26(arry_p, curve_p);
	 set_prime(vec_pp, arry_p);
	 vec vec_multi_pp[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 r[i] = VADD(vec_pp[i], VSUB(x[i], y[i]));
	 }
	 for (i = 0; i < NLIMB / 2; i++)//减少后面循环次数
	 {
		 vec_multi_pp[i] = VSHL(vec_pp[i], 14);
	 }
	 while (!test_limbsign(r))
	 {
		 for (i = 0; i < NLIMB / 2; i++)
		 {
			 r[i] = VADD(r[i], vec_multi_pp[i]);
		 }
	 }
	 
	 
 }
 void vec_2w_add(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2])
 {
	 int i = 0;
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 r[i] = VADD(x[i],  y[i]);
	 }
 }
 void vec_2w_modsqr(vec r[NLIMB / 2], const vec x[NLIMB / 2])
 {
	 int i, j;
	 vec T, W, S, X, Z[NLIMB] = { VZERO }, U[NLIMB] = { VZERO }, V[NLIMB] = { VZERO };
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 j = (i + 1) % 5;
		 j = (j < 0) ? (j + 5) : j;
		 U[2 * i] = x[i];
		 U[2 * i + 1] = ALIGNR(x[j], x[i]);
		 V[2 * i] = SHUFPD(x[i], x[i], 0X00);
		 V[2 * i + 1] = SHUFPD(x[i], x[i], 0X0F);
	 }
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 T = VMUL(U[i], V[i]);
		 Z[i] = BLEND32(T, VZERO, 0XCC);
		 W = BLEND32(T, VZERO, 0X33);
		 for (j = 1; j <= i; j++)
		 {
			 int t = (i - j) % NLIMB;
			 t = (t < 0) ? (t + NLIMB) : t;
			 W = VADD(W, VMUL(U[i+j], V[t]));
		 }
		 Z[i] = VADD(Z[i], VSHL(W, 0x01));
		 S = VMUL(U[i + 5], V[i + 5]);
		 Z[i + 5] = BLEND32(S, VZERO, 0XCC);
		 X = VZERO;
		 for (j = i + 1; j < NLIMB / 2; j++)
		 {
			 int t = (i - j) % NLIMB;
			 t = (t < 0) ? (t + NLIMB) : t;
			 X = VADD(X, VMUL(U[i+j], V[t]));
		 }
		 Z[i + 5] = VADD(Z[i + 5], VSHL(X, 0x01));
	 }
	 vec_2w_fastred(r, Z);
 }
 void vec_2w_modmul(vec r[NLIMB / 2], const vec x[NLIMB / 2], const vec y[NLIMB / 2])
 {
	 int i,j;
	 vec Z[NLIMB] = {VZERO},  CD[NLIMB / 2];
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 j = (i + 1) % 5;
		 j = (j < 0) ? (j + 5) : j;
		 CD[i] = ALIGNR(y[j], y[i]);
	 }
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 vec U = SHUFPD(x[i], x[i], 0x00);
		 for (j = 0; j < NLIMB / 2; j++)
		 {
			 Z[i + j] = VADD(Z[i + j], VMUL(U, y[j]));
		 }
		 vec V = SHUFPD(x[i], x[i], 0x0F);
		 for (j = 0; j < NLIMB / 2 - 1; j++)
		 {
			 Z[i + j + 1] = VADD(Z[i + j + 1], VMUL(V, CD[j]));
		 }
		 vec W = VMUL(V, CD[4]); //<C',D'>
		 Z[i] = VADD(Z[i], BLEND32(W, VZERO, 0x33));
		 Z[i + 5] = VADD(Z[i + 5], BLEND32(W, VZERO, 0xCC));
	 }
	 vec_2w_fastred(r,Z);
 }
 void vec_2w_fastred(vec r[NLIMB / 2], vec Z[NLIMB])
 {
	 //process 0:
	 int i = 0, j = 0;
	 vec VMASK26 = VSET164(MASK26);
	 vec L[NLIMB] = { VZERO }, M[NLIMB] = { VZERO }, H[NLIMB] = { VZERO }, M_M[NLIMB] = { VZERO };
	 for (i = 4; i <= 8; i++)
	 {
		 L[i] = VAND(Z[i], VMASK26);
		 M[i] = VSHR(Z[i], 26);
		 M[i] = VAND(M[i], VMASK26);
		 H[i] = VSHR(Z[i], 2 * 26);
	 }
	 L[9] = VAND(Z[9], VMASK26);
	 M[9] = VSHR(Z[9], 26);
	 for (i = 5; i <= 9; i++)
	 {
		 M_M[i] = ALIGNR(M[i], M[i - 1]);
		 Z[i] = VADD(VADD(L[i], M_M[i]), H[i - 1]);
	 }
	 //算法此处有问题，自己添加
	 Z[4] = VAND(Z[4], VSET64(MASK26, MASK52, MASK26, MASK52));
	 //Z[9] = ALIGNR(Z[9], M[9]);   

	 //process1:vec_2w_simplered(r, Z); 
	 //r[1]
	 r[0] = VADD(Z[0], VSHL(Z[5], 4));
	 r[0] = VADD(r[0], VSHL(Z[6], 24));
	 r[0] = VADD(r[0], VSHL(SHUFPD(Z[6], Z[7], 0x05), 18));
	 r[0] = VADD(r[0], VSHL(Z[7], 12));
	 r[0] = VADD(r[0], VSHL(SHUFPD(Z[7], Z[8], 0X05), 6));
	 r[0] = VADD(r[0], VSHL(Z[9], 21));
	 r[0] = VADD(r[0], VSHLV(BLEND32(VPERM64(Z[9], 0XB1), Z[8], 0XCC), VSET64(1, 15, 1, 15)));
	 vec Z8 = VSUB(VZERO, Z[8]);//Z8'
	 vec Z9 = VSUB(VZERO, Z[9]);//Z9'

	 //r[1]
	 r[1] = VSUB(Z[1], VSHL(Z[5], 16));
	 r[1] = VADD(r[1], VSHLV(BLEND32(Z[6], VPERM64(Z[5], 0XB1), 0XCC), VSET64(22, 4, 22, 4)));
	 r[1] = VSUB(r[1], VSHLV(SHUFPD(VZERO, Z[6], 0x05), VSET64(10, 0, 10, 0)));
	 r[1] = VADD(r[1], VSHL(BLEND32(Z[8], Z8, 0XCC), 12));
	 r[1] = VADD(r[1], VSHL(SHUFPD(Z[8], Z9, 0X05), 6));
	 r[1] = VADD(r[1], VSHLV(BLEND32(Z[9], Z[7], 0XCC), VSET64(24, 1, 24, 1)));

	 //r[2]
	 r[2] = VADD(Z[2], VSHL(SHUFPD(Z[5], Z[6], 0X05), 22));
	 r[2] = VADD(r[2], VSHL(Z[7], 4));
	 r[2] = VADD(r[2], VSHL(Z[8], 24));
	 r[2] = VADD(r[2], VSHL(SHUFPD(Z[8], Z[9], 0X05), 19));
	 r[2] = VADD(r[2], VSHL(Z[9], 12));
	 r[2] = VADD(r[2], VSHL(SHUFPD(Z[9], VZERO, 0X05), 6));

	 //r[3]
	 r[3] = VADD(Z[3], VSHL(SHUFPD(Z[6], Z[7], 0X05), 22));
	 r[3] = VADD(r[3], VSHL(Z[8], 4));
	 r[3] = VADD(r[3], VSHL(Z[9], 24));
	 r[3] = VADD(r[3], VSHL(SHUFPD(Z[9], VZERO, 0X05), 19));

	 //r[4]
	 r[4] = VADD(Z[4], VSHL(Z[5], 20));
	 r[4] = VADD(r[4], VSHLV(SHUFPD(Z[7], Z[7], 0x05), VSET64(2, 23, 2, 23)));
	 r[4] = VADD(r[4], VSHL(Z[9], 4));
	 vec T = VADD(VSHLV(Z[6], VSET64(8, 14, 8, 14)), VSHLV(Z[8], VSET64(17, 23, 17, 23)));
	 T = VADD(T, VSHLV(Z[9], VSET64(5, 11, 5, 11)));
	 r[4] = VADD(r[4], VADD(SHUFPD(VZERO, T, 0X05), BLEND32(VZERO, T, 0XCC)));//位置
	 //处理r0-r3负数借位情况,先把carry前的值记录下来，caryy后处理借位,实际只有r2的limb可能出现负数，最后修改为针对r2的借位
	 for (i = 0;i < NLIMB / 2 - 1;i++)
	 {
		 long long int* lo = (long long int*) & r[i];
		 if (lo[0] < 0 || lo[1] < 0 || lo[2] < 0 || lo[3] < 0)
		 {
			 //低位有借位
			 if (lo[0] < 0 && lo[2] < 0)
			 {
				 r[i + 1] = VSUB(r[i + 1], VSET64(0, MASK13, 0, MASK13));
				 if (lo[1] < 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, MASK13, 0));
				 if (lo[1] < 0 && lo[3] >= 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(0, 0, MASK13, 0));
				 if (lo[1] >= 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, 0, 0));
				 //if (lo[1] >= 0 && lo[2] >= 0);
			 }
			 else if (lo[0] < 0 && lo[2] >= 0)
			 {
				 r[i + 1] = VSUB(r[i + 1], VSET64(0, 0, 0, MASK13));
				 if (lo[1] < 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, MASK13, 0));
				 if (lo[1] < 0 && lo[3] >= 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(0, 0, MASK13, 0));
				 if (lo[1] >= 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, 0, 0));
				 //if (lo[1] >= 0 && lo[2] >= 0);
			 }
			 else if (lo[0] >= 0 && lo[2] < 0)
			 {
				 r[i + 1] = VSUB(r[i + 1], VSET64(0, MASK13, 0, 0));
				 if (lo[1] < 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, MASK13, 0));
				 if (lo[1] < 0 && lo[3] >= 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(0, 0, MASK13, 0));
				 if (lo[1] >= 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, 0, 0));
				 //if (lo[1] >= 0 && lo[2] >= 0);
			 }
			 else
			 {
				 if (lo[1] < 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, MASK13, 0));
				 if (lo[1] < 0 && lo[3] >= 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(0, 0, MASK13, 0));
				 if (lo[1] >= 0 && lo[3] < 0)
					 r[i + 1] = VSUB(r[i + 1], VSET64(MASK13, 0, 0, 0));
			 }
		 }
		 else
			 continue;
	 }

	//process2:vec_2w_carry(r); //in place carry
	 vec_2w_carry(r);
 }
 void vec_2w_carry(vec r[NLIMB / 2])
 {
	 //默认输入r的权重最大为10*26
	 int i, j;
	 vec VMASK26 = VSET164(MASK26);
	 vec H[NLIMB / 2], M[NLIMB / 2], L[NLIMB / 2], M_M[NLIMB / 2];
	 
	 //处理权重10*26
	 H[4] = VSHRV(r[4], VSET64(26, 2 * 26, 26, 2 * 26));
	 r[4] = VAND(r[4], VSET64(MASK26, MASK52, MASK26, MASK52));
	 vec Q = VADD(H[4], SHUFPD(H[4], H[4], 0X05));
	 vec Q_Q = VSUB(VZERO, Q);
	 r[0] = VADD(r[0], VSHLV(BLEND32(Q, VZERO, 0XCC), VSET64(0, 4, 0, 4)));
	 r[1] = VADD(r[1], VSHLV(BLEND32(Q, Q_Q, 0X33), VSET64(22, 16, 22, 16)));
	 r[4] = VADD(r[4], VSHLV(BLEND32(Q, VZERO, 0XCC), VSET64(0, 20, 0, 20)));
	 //上步可能导致z8存在26-52bit内容，处理权重10*26
	 H[4] = VSHRV(r[4], VSET64(26, 2 * 26, 26, 2 * 26));
	 r[4] = VAND(r[4], VSET64(MASK26, MASK52, MASK26, MASK52));
	 Q = VADD(H[4], SHUFPD(H[4], H[4], 0X05));
	 Q_Q = VSUB(VZERO, Q);
	 r[0] = VADD(r[0], VSHLV(BLEND32(Q, VZERO, 0XCC), VSET64(0, 4, 0, 4)));
	 r[1] = VADD(r[1], VSHLV(BLEND32(Q, Q_Q, 0X33), VSET64(22, 16, 22, 16)));
	 r[4] = VADD(r[4], VSHLV(BLEND32(Q, VZERO, 0XCC), VSET64(0, 20, 0, 20)));
	 
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 L[i] = VAND(r[i], VMASK26);
		 M[i] = VSHR(r[i], 26);
		 M[i] = VAND(M[i], VMASK26);
		 H[i] = VSHR(r[i], 2 * 26);
	 }
	 for (i = 0; i < NLIMB / 2; i++)
	 {
		 //j = i - (i / j);//取模运算
		 j = (i - 1) % 5;
		 j = (j < 0) ? (j + 5) : j;
		 M_M[i] = ALIGNR(M[i], M[j]);
		 r[i] = VADD(VADD(L[i], M_M[i]), H[j]);
	 }
 }

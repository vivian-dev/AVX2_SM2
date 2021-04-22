#include"test.h"
#include"timing.h"

void print_sm2info()
{
	int i;
	printf("********************************SM2 Parameter*****************************\n");
	printf("*                                                                        *\n");
	printf("* p=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_p[i]);
	printf(" *");
	printf("\n*                                                                        *\n");
	printf("* a=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_a[i]);
	printf(" *");
	printf("\n*                                                                        *\n");
	printf("* b=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_b[i]);
	printf(" *");
	printf("\n*                                                                        *\n");
	printf("* Gx=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_G.x[i]);
	printf("*");
	printf("\n*                                                                        *\n");
	printf("* Gy=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_G.y[i]);
	printf("*");
	printf("\n*                                                                        *\n");
	printf("* n=");
	for (i = NUM_DIGITS_SM2 - 1; i >= 0; i--)
		printf("%016llx ", curve_n[i]);
	printf(" *\n");
	printf("**************************************************************************\n\n");
}
int main()
{
	print_sm2info();
	for (int k = 0; k < 200; k++)
	{
		printf("==========================================================================\n");
		printf("          Fast Implementation of SM2 Elliptic Curve Cryptography     \n");
		printf("                     Using AVX2 Vector Instructions              \n");
		printf("==========================================================================\n\n");
		printf("=========================== Start of Functional Test =====================\n");
		test_all();
		printf("\n=========================== End of Functional Test =======================\n\n");
		
		printf("\n========================== Start of Benchmarking =========================\n");
		timing_all();
		printf("============================ End of Benchmarking =========================\n");

		system("pause");
	}
	return 0;
}
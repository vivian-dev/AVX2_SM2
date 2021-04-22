#ifndef TIMING_H
#define TIMING_H
#include<stdlib.h>
#include<time.h>
#include<Windows.h>
#include<string.h>
#include "pfd.h"
#include"limb.h"
#include"sm2.h"
#include"curve.h"

//#define TEST_TIMES 100

#define CLOCK(TEST_TIMES,LABEL, FUNCTION)                           \
  do																\
  {                                                                 \
		int i;														\
		uint64_t start_time, end_time;								\
		for (i = 0; i < 1000; i++) FUNCTION;						\
		start_time = GetTickCount64();								\
		for (i = 0; i < TEST_TIMES; i++)							\
		{															\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
		}															\
		end_time = GetTickCount64();								\
		printf("timing %s\n",LABEL);								\
		printf("  - Total time : %lld ms\n", end_time-start_time);	\
		if((strcmp(LABEL,"2w_add")==0)||(strcmp(LABEL,"2w_sub")==0)||(strcmp(LABEL,"2w_mul")==0)||(strcmp(LABEL,"2w_sqr")==0))\
			printf("  - (2-way)Throughput: %8.1f op/sec\n", 1e3 * 20 * TEST_TIMES / (double)(end_time-start_time));\
		else														\
			printf("  - Throughput: %8.1f op/sec\n", 1e3 * 10 * TEST_TIMES / (double)(end_time-start_time));\
  } while (0)

#define test_function(TEST_TIMES,LABEL, FUNCTION) CLOCK(TEST_TIMES, LABEL, FUNCTION)

void timing_sm2();
void timing_fp_arith();
void timing_point_arith();
void timing_all();
void timing_part();

#endif
#pragma once

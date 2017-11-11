//
//  btest.h
//  unit_testing
//
//  Created by HENRY BERGIN on 10/31/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

// Simple testing library for C

#ifndef btest_h
#define btest_h

#include <sys/types.h>
#include "_types/_uint32_t.h"
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

#define STRINGIFY(x) #x
#define CONCAT(x, y) STRINGIFY(x ## y)

#define ADD_TEST(test_group, test_name) btest_add_test(test_group ## _ ## test_name, \
CONCAT(test_group, _  ## test_name))
#define TEST(test_group, test_name) void test_group ## _ ## test_name()

#define EXPECT_TRUE(x) expect_true(x, __func__, __FILE__, __LINE__)
#define EXPECT_FALSE(x) expect_false(x, __func__, __FILE__, __LINE__)
#define EXPECT_EQ_INT(x,y) expect_equal_int(x, y, __func__, __FILE__, __LINE__)
#define EXPECT_EQ_STR(x,y,s) expect_equal_str(x, y, s, __func__, __FILE__, __LINE__)


void btest_start_testing();
void btest_add_test(void (*testf)(), const char *name);
void expect_true(uint8_t val, const char *test_name, const char *filename, uint16_t line);
void expect_false(uint8_t val, const char *test_name, const char *filename, uint16_t line);
void expect_equal_int(uint32_t x, uint32_t y, const char *test_name, const char *filename, uint16_t line);
void expect_equal_str(const char *x, const char *y, uint16_t size, const char *test_name, const char *filename, uint16_t line);
void get_file_line(const char *filename, uint16_t line, char *line_str, uint16_t line_str_size);

#endif /* btest_h */

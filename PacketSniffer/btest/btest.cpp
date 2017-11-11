//
//  btest.c
//  unit_testing
//
//  Created by HENRY BERGIN on 10/31/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

// Modeled after gtest. Boost test and google test both seem to use
// static intitialization of objects to register the test function
// at runtime. This isn't possible with C so you need to register
// the tests manually. Maybe it would be possible to peek in the object
// files to find the function addresses, but that could get messy.

// Test report should print the line that failed.

// An external function table map file could be cool (addresses to functions that could be read anywhere).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "btest.h"
#include "linked_list.h"

void get_file_line(char *filename, uint16_t line, char *line_str, uint16_t line_str_size)
{
    FILE *code_file;
    
    code_file = fopen(filename, "r");
    char code_c = fgetc(code_file);
    uint16_t line_count = 0;
    while(code_c != EOF && (line_count+1) < line)
    {
        if(code_c == '\n')
        {
            line_count++;
        }
        code_c = fgetc(code_file);
    }
    
    for(uint16_t i = 0; i < line_str_size && code_c != '\n'; i++)
    {
        line_str[i] = code_c;
        code_c = fgetc(code_file);
    }
    
    fclose(code_file);
}

typedef struct
{
    char *failed_line_string;
    char *failed_input;
    char *test_name;
    uint16_t line_number;
}R_node;

void report_node_dealloc(void *data)
{
    R_node *report_node = (R_node *)(data);
    free(report_node->failed_line_string);
    free(report_node->test_name);
    free(report_node->failed_input);
    report_node->failed_line_string = NULL;
    report_node->test_name          = NULL;
    report_node->failed_input       = NULL;
}

typedef struct
{
    char name[100];
    void (*test_ptr)(void); // function pointer
    uint16_t failedCount; // 0 -> pass    >0 -> number failed
}T_node;

void test_node_dealloc(void *data)
{

}

list_node *test_head = NULL;
list_node *report_head = NULL;

void add_test_report(R_node node)
{
    ll_add_node(&report_head, &node, sizeof(node));
}

void add_test_node(T_node node)
{
    ll_add_node(&test_head, &node, sizeof(node));
}

void update_test_status(const char *test_name, uint8_t passfail)
{
    list_node *current_node = test_head;
    T_node *data_node = (T_node *)ll_data(current_node);
    
    while(data_node != NULL && strcmp(data_node->name,test_name))
    {
        data_node = (T_node *)ll_data(current_node);
        ll_iterate(&current_node);
    }
    
    if(!passfail) data_node->failedCount++; // increment the number of failed tests
    
}


void btest_add_report(const char *test_name, char *filename, char *failed_input, uint16_t line)
{
    R_node report;
    report.test_name = (char *)malloc((uint8_t)strlen(test_name)+1);
    strcpy(report.test_name, test_name);
    char fail_line[200] = {0};
    get_file_line(filename, line, fail_line, 200);
    report.failed_line_string = (char *)malloc((uint8_t)strlen(fail_line)+1);
    strcpy(report.failed_line_string, fail_line);
    report.failed_input = (char *)malloc((uint8_t)strlen(failed_input)+1);
    strcpy(report.failed_input, failed_input);
    report.line_number = line;
    
    ll_add_node(&report_head, &report, sizeof(report));
}

void expect_equal_str(char *x, char *y, uint16_t size, const char *test_name, char *filename, uint16_t line)
{
    uint8_t passfail = 1;
    uint16_t i = 0;
    for(; (x[i] != '\0' && y[i] != '\0') && (x[i] == y[i]) && (i < size); i++)
    {
        
    }
    if(i < (size))
    {
        passfail = 0;
    }
    
    if(passfail)
    {
        printf("%s: EXPECT EQUAL STR PASSED\n", test_name);
        update_test_status(test_name, 1);
    }
    else
    {
        printf("-> %s: EXPECT EQUAL STR FAILED\n", test_name);
        update_test_status(test_name, 0);
        uint8_t sz = sizeof("EXPECT_EQ_STR(,)") + strlen(x) + strlen(y) + 1;
        char *failed_input = (char *)malloc(sz);
        sprintf(failed_input, "EXPECT_EQ_INT(%s,%s)", x,y);
        
        btest_add_report(test_name, filename, failed_input, line);
        
    }
}

void expect_equal_int(uint32_t x, uint32_t y, const char *test_name, char *filename, uint16_t line)
{
    if(x == y)
    {
        printf("%s: EXPECT EQUAL INT PASSED\n", test_name);
        update_test_status(test_name, 1);
    }
    else
    {
        printf("-> %s: EXPECT EQUAL INT FAILED\n", test_name);
        update_test_status(test_name, 0);
        
        uint8_t sz = sizeof("EXPECT_EQ_INT(,)") + x/10 + y/10 + 2;
        char *failed_input = (char *)malloc(sz);
        sprintf(failed_input, "EXPECT_EQ_INT(%d,%d)", x,y);
        
        btest_add_report(test_name, filename, failed_input, line);
    }
}

void expect_true(uint8_t val, const char *test_name, char *filename, uint16_t line)
{
    if(val)
    {
        printf("%s: EXPECT TRUE PASSED\n", test_name);
        update_test_status(test_name, 1);
    }
    else
    {
        printf("-> %s: EXPECT TRUE FAILED\n", test_name);
        update_test_status(test_name, 0);
        
        uint8_t sz = sizeof("EXPECT_TRUE()") + val/10 + 1;
        char *failed_input =(char *)malloc(sz);
        sprintf(failed_input, "EXPECT_TRUE(%d)", val);
        
        btest_add_report(test_name, filename, failed_input, line);

    }
}

void expect_false(uint8_t val, const char *test_name, char *filename, uint16_t line)
{
    if(!val)
    {
        printf("%s: EXPECT FALSE PASSED\n", test_name);
        update_test_status(test_name, 1);
    }
    else
    {
        printf("-> %s: EXPECT FALSE FAILED\n", test_name);
        update_test_status(test_name, 0);
        
        uint8_t sz = sizeof("EXPECT_FALSE()") + val/10 + 1;
        char *failed_input = (char *)malloc(sz);
        sprintf(failed_input, "EXPECT_FALSE(%d)", val);
        
        btest_add_report(test_name, filename, failed_input, line);
        
    }
}

void btest_add_test(void (*testf)(), const char *name)
{ // should probably be a list of function pointers that is static. Then the start test
  // function would walk down the list calling each test
    
    T_node node;
    strcpy(node.name, name);
    node.test_ptr = (void(*)())testf;
    node.failedCount = 0; // start out as all tests failing
    
    ll_add_node(&test_head, &node, sizeof(node));
    
    printf("adding test: %s\n",node.name);
}

void btest_run_all_tests()
{
    list_node *current_node = test_head;
    while(current_node != NULL)
    {
        printf("==============================\n\n");
        printf("====running %s====\n", ((T_node *)ll_data(current_node))->name);
        (*(((T_node *)ll_data(current_node))->test_ptr))(); // run the test
        ll_iterate(&current_node);
    }
    printf("==============================\n\n");
}

void btest_teardown()
{ // walk down the list and delete the test
    ll_teardown(test_head, test_node_dealloc);
    ll_teardown(report_head, report_node_dealloc);
}

void btest_report()
{
    list_node *current_node = test_head;
    T_node *data_node;
    uint16_t failed_tests_count = 0;
    
    while(current_node != NULL)
    {
        data_node = (T_node *)ll_data(current_node);
        if(data_node->failedCount > 0) failed_tests_count += data_node->failedCount;
        ll_iterate(&current_node);
    }
    
    printf("failed tests: %d\n\n", failed_tests_count); // this could be more specific eventually
                                                      // i.e. which tests failed as a whole, and which part
    
    current_node = report_head;
    R_node *report_node;
    while(current_node != NULL)
    {
        report_node = (R_node *)ll_data(current_node);
        printf("%s: %s: line %d: %s\n\n",report_node->test_name,report_node->failed_input,report_node->line_number,report_node->failed_line_string);
        ll_iterate(&current_node);
    }
}

void btest_start_testing()

{
    
    printf("++++++++ BTEST +++++++++\n");

    printf("starting testing...\n\n");
    btest_run_all_tests();

    printf("======== testing report ========\n");
    btest_report();
    printf("================================\n\n");
    
    printf("tearing down testing...\n");
    btest_teardown();
    printf("testing completed...\n");

    printf("++++++++++++++++++++++++\n\n\n");
    
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

int test_add(int a, int b) {
    return a + b;
}

float test_addf(float a, float b) {
    return a + b;
}

double test_addd(double a, double b) {
    return a + b; 
}

void* test_malloc(int size) {
    assert(size > 10);
    uint8_t* val = malloc(size);
    memcpy(val, "hello", 6);
    return val;
}


bool test_str(char* str){
    printf("from js: %s\n", str);
    return true;
}
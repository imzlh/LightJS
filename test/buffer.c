#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdbool.h>
#include "../src/utils.h"

void test_buffer_init() {
    struct Buffer* buffer;
    uint8_t* data = (uint8_t*)malloc(10);
    buffer_init(&buffer, data, 10);
    assert(buffer -> buffer == data);
    assert(buffer -> size == 10);
    assert(buffer -> start == 0);
    assert(buffer -> end == 0);
    assert(buffer -> is_dynamic == false);
    buffer_free(buffer);

    buffer_init(&buffer, NULL, 10);
    assert(buffer -> buffer != NULL);
    assert(buffer -> size == 10);
    assert(buffer -> start == 0);
    assert(buffer -> end == 0);
    assert(buffer -> is_dynamic == true);
    buffer_free(buffer);
}

void test_buffer_push_pop() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "hello";
    uint8_t dest[10];
    assert(buffer_push(buffer, data, 5) == 5);
    assert(buffer_used(buffer) == 5);
    assert(buffer_pop(buffer, dest, 5) == 5);
    assert(memcmp(dest, data, 5) == 0);
    assert(buffer_is_empty(buffer));

    buffer_free(buffer);
}

void test_buffer_seek() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    assert(buffer_seek(buffer, 5) == true);
    assert(buffer -> start == 5);
    assert(buffer -> end == 5);

    assert(buffer_seek(buffer, 5) == true);
    assert(buffer -> start == 0);
    assert(buffer -> end == 0);

    buffer_free(buffer);
}

void test_buffer_available_used() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    assert(buffer_available(buffer) == 9);
    assert(buffer_used(buffer) == 0);

    uint8_t data[] = "hello";
    buffer_push(buffer, data, 5);

    assert(buffer_available(buffer) == 4);
    assert(buffer_used(buffer) == 5);

    buffer_free(buffer);
}

void test_buffer_is_empty_full() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    assert(buffer_is_empty(buffer) == true);
    assert(buffer_is_full(buffer) == false);

    uint8_t data[] = "123456789";
    buffer_push(buffer, data, 9);

    assert(buffer_is_empty(buffer) == false);
    assert(buffer_is_full(buffer) == true);

    buffer_pop(buffer, data, 9);

    assert(buffer_is_empty(buffer) == true);
    assert(buffer_is_full(buffer) == false);

    buffer_free(buffer);
}

void test_buffer_clear() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "hello";
    buffer_push(buffer, data, 5);

    buffer_clear(buffer);
    assert(buffer_is_empty(buffer));
    assert(buffer -> start == 0);
    assert(buffer -> end == 0);

    buffer_free(buffer);
}

void test_buffer_read_write() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    int fd = open("/tmp/test_buffer_read_write", O_RDWR | O_CREAT, 0666);
    assert(fd >= 0);
    uint8_t data[] = "hello";
    write(fd, data, 5);
    lseek(fd, 0, SEEK_SET);

    assert(buffer_read(buffer, fd, 5) == 5);
    assert(buffer_used(buffer) == 5);

    lseek(fd, 0, SEEK_SET);
    assert(buffer_write(buffer, fd, 5) == 5);
    close(fd);
    unlink("/tmp/test_buffer_read_write");

    buffer_free(buffer);
}

void test_buffer_realloc() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    assert(buffer_realloc(buffer, 20, false) == true);
    assert(buffer -> size == 20);

    uint8_t data[] = "123456789";
    buffer_push(buffer, data, 9);
    assert(buffer_realloc(buffer, 5, true) == true);
    assert(buffer -> size == 5);
    assert(buffer_used(buffer) == 4); // last byte lost due to insufficient space

    buffer_free(buffer);
}

void test_buffer_export() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "hello";
    buffer_push(buffer, data, 5);

    uint32_t size;
    uint8_t* export_data = buffer_export(buffer, &size);
    assert(size == 5);
    assert(memcmp(export_data, data, 5) == 0);
    free(export_data);

    buffer_free(buffer);
}

void test_buffer_copyto() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "hello";
    buffer_push(buffer, data, 5);

    uint8_t dest[10];
    assert(buffer_copyto(buffer, dest, 5) == 5);
    assert(memcmp(dest, data, 5) == 0);

    buffer_free(buffer);
}

void test_buffer_sub_export() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "hello";
    buffer_push(buffer, data, 5);

    uint32_t size;
    uint8_t* sub_data = buffer_sub_export(buffer, 1, 4, &size);
    assert(size == 3);
    assert(memcmp(sub_data, "ell", 3) == 0);
    free(sub_data);

    buffer_free(buffer);
}

void test_buffer_expand() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "123456789";
    buffer_push(buffer, data, 9);

    assert(buffer_flat(buffer) == true);
    assert(buffer -> start == 0);
    assert(buffer -> end == 9);

    buffer_free(buffer);
}

void test_buffer_offset() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    uint8_t data[] = "123456789";
    buffer_push(buffer, data, 9);  // start=0, end=9

    assert(buffer_offset(buffer, 3, false) == true);
    assert(buffer -> start == 0);    // 展开后数据从0开始
    assert(buffer -> end == 6);      // 9-3=6
    assert(buffer_used(buffer) == 6);
    
    // 验证数据内容
    uint8_t dest[10];
    buffer_pop(buffer, dest, 6);
    assert(memcmp(dest, "456789", 6) == 0);

    buffer_free(buffer);
}

void test_buffer_aligned() {
    struct Buffer* buffer;
    buffer_init(&buffer, NULL, 10);

    buffer_aligned(buffer, 16);
    assert(((uintptr_t)buffer -> buffer & 15) == 0);

    buffer_free(buffer);
}

void test_buffer_merge() {
    struct Buffer* buffer1;
    buffer_init(&buffer1, NULL, 10);
    struct Buffer* buffer2;
    buffer_init(&buffer2, NULL, 10);

    uint8_t data1[] = "hello";
    buffer_push(buffer1, data1, 5); // used=5

    uint8_t data2[] = "world";
    buffer_push(buffer2, data2, 5); // used=5

    assert(buffer_merge(buffer1, buffer2) == true);
    printf("buffer1 -> used=%d\n", buffer_used(buffer1));
    assert(buffer_used(buffer1) == 10);
    assert(buffer1 -> size == 11);
    
    buffer_free(buffer1);
}

int main() {
    test_buffer_init();
    test_buffer_push_pop();
    test_buffer_seek();
    test_buffer_available_used();
    test_buffer_is_empty_full();
    test_buffer_clear();
    test_buffer_read_write();
    test_buffer_realloc();
    test_buffer_export();
    test_buffer_copyto();
    test_buffer_sub_export();
    test_buffer_expand();
    test_buffer_offset();
    test_buffer_aligned();
    test_buffer_merge();
    printf("All tests passed!\n");
    return 0;
}
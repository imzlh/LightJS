#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syscall.h>
#include <unistd.h>

int main() {
    aio_context_t ctx;
    int ret = syscall(__NR_io_setup, 64, &ctx);
    if (ret < 0) {
        perror("io_setup");
        printf("Error code: %d\n", errno);
    } else {
        printf("Success!\n");
    }
    return 0;
}

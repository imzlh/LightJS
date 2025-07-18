#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <termios.h>

#include "../src/core.h"

int count = 0;
int reply_handler(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data) {
    printf("Reply(size=%d): %s\n", read_size, buffer);
    if(read_size == 0 || (count++) == 10) return EVCB_RET_DONE;
    return EVCB_RET_CONTINUE;
}

int main() {
    evcore_init();

    // ttyRaw
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                            |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    tty.c_cflag &= ~(CSIZE | PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    EvFD* in = evfd_new(0, false, true, false, 1024, NULL, NULL);
    EvFD* out = evfd_new(1, false, false, true, 1024, NULL, NULL);

    evfd_write(out, "Hello!(reply) > ", 16, NULL, NULL);
    evfd_read(in, 100, malloc(100), reply_handler, NULL);
    
    evcore_run(NULL, NULL);

    return 0;
}
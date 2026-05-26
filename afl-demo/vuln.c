#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    FILE *fp;
    char buf[64];

    if (argc < 2) {
        return 0;
    }

    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        return 0;
    }

    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);

    buf[n] = '\0';

    if (n >= 4) {
        if (buf[0] == 'A') {
            if (buf[1] == 'F') {
                if (buf[2] == 'L') {
                    if (buf[3] == '!') {
                        char *p = NULL;
                        *p = 'X';   // intentional crash
                    }
                }
            }
        }
    }

    return 0;
}
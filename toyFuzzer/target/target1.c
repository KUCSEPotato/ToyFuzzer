// target1.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 0;

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    if (strstr(buf, "FUZZ") && strstr(buf, "CRASH")) {
        int *p = NULL;
        *p = 123;
    }

    return 0;
}
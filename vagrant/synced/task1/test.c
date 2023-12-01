#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <locale.h>

void rec_func(int n) {
    rec_func(n -1);
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    int n = rand();
    if (n) {
        rec_func(10);
    }
    return 0;
}
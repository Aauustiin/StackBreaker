#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int b(int i) {
    i --;
    if (i > 0) b(i);
    printf("in func b\n");
    return 0;
}

int a(char *s) {
    char buf[32];
    strcpy(buf, s);
    printf("in func a\n");
    return 0;
}

int main() {
    srand(time(NULL));
    int r = rand();

    char s[] = "hello";

    printf("hello\n");

    if (r % 2 == 0){
        a(s);
    }
    else b(4);

    return 0;
}
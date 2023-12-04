#include <stdio.h>

int fun(FILE* f) {
    char buf[2];
    char i = 0;
    char c;
    while (1) {
        c = fgetc(f);
        if (c != EOF) buf[i] = c;
        else break;
        i++;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    FILE* f = fopen("exploit", "rb");
    printf("Address of printf: %p\n", &printf);
    printf("Addres of fun: %p\n", &fun);
    fun(f);
    fclose(f);
    return 0;
}

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int decide(char *string) {
    if (strlen(string) > 100) return 0;
    if (string[0] != 'h') return 0;
    if (string[1] != 'e') return 0;
    if (string[2] != 'l') return 0;
    if (string[3] != 'l') return 0;
    if (string[4] != 'o') return 0;
    if (string[5] != '\n') return 0;

    char buf[101];
    strcpy(buf, string);
    printf("hi!\n");
    return 0;
}

int main(int argc, char *argv[]) {
    char buffer[700];
    FILE *file;
    if (argc !=2)
    {
        printf("[*] invalid arguments!\n [*] > %s file_name\n",argv[0]);
        exit(0);
    }
    file = fopen(argv[1], "rb");
    if (!file) {
        fprintf(stderr,"file not opened %s", strerror(errno));
        return(0);
    }
    fread(buffer, 699, 1, file);
    fclose(file);
    if (strlen(buffer) < 100) {
    decide(buffer);
    }
    return(0);
}
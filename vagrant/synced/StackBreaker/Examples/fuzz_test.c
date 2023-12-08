#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int b() {
    printf("hello!");
}

int a(char *string) {
   char buf[32];

   if (strlen(string) > 50){
        strcpy(buf, string);
   } 

   return 0;
}

int main(int argc, char *argv[]) {
    char buffer[700];
    FILE *file;
    file = fopen(argv[1], "rb");
    if (!file) {
        fprintf(stderr,"file not opened %s", strerror(errno));
        return(0);
    }
    fread(buffer, 699, 1, file);
    fclose(file);
    if (strlen(buffer) < 100) {
        a(buffer);
    }
    else b();

    return(0);
}
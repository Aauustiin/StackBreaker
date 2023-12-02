#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int copyData(char *string)
{
	char buf[128];
	strcpy(buf, string);
	return (0);
}

int main(int argc, char *argv[])
{
	if (argc !=1)
    {
        printf("[*] invalid arguments!\n");
        exit(0);
    }
	char buffer[700];
	scanf("%s", &buffer);
	copyData(buffer);
	return (0);
}

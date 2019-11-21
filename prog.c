#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define FILE_PATH "/home/eden/Downloads/Syscall-SO-master/omg.txt"

ssize_t write_crypt(int fd, const void *buf, size_t nbytes) { return syscall(548, fd, buf, nbytes); }
ssize_t read_crypt(int fd, const void *buf, size_t nbytes) { return syscall(549, fd, buf, nbytes); }

int main() {

	char text[100];

	int fd = open(FILE_PATH, O_WRONLY|O_CREAT, 0666);

	printf("Digite um texto [max. 100 carac.]: ");
	scanf("%[^\n]", text);

	ssize_t r = write_crypt(fd,text,strlen(text));
	printf("Returned %d\n", (int)r);

	close(fd);
	fd = open(FILE_PATH, O_RDONLY|O_CREAT, 0666);

	char receive[100];

	r = read_crypt(fd,receive,strlen(text));
	receive[strlen(text)] = 0;

	printf("Returned %d\n", (int)r);
	printf("Recebido: %s\n", receive);	
}

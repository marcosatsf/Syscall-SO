#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

ssize_t write_crypt(int fd, const void *buf, size_t nbytes) { return syscall(548, fd, buf, nbytes); }
ssize_t read_crypt(int fd, const void *buf, size_t nbytes) { return syscall(549, fd, buf, nbytes); }

int main() {

	char text[100];

	int fd = open("/home/puc/Documentos/fvck.txt", O_WRONLY|O_CREAT, 0666);

	printf("Digite um texto [max. 100 carac.]: ");
	scanf("%[^\n]", text);

	ssize_t r = write_crypt(fd,text,strlen(text));
	//ssize_t r = syscall(548, fd, "abcde", 5);
	printf("Returned %d\n", (int)r);

	close(fd);
	fd = open("/home/puc/Documentos/fvck.txt", O_RDONLY|O_CREAT, 0666);

	char receive[100];

	r = read_crypt(fd,receive,strlen(text));

	printf("Returned %d\n", (int)r);
	printf("Recebido: %s\n", receive);	
}

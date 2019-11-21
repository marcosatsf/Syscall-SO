#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

ssize_t write_crypt(int fd, const void *buf, size_t nbytes) { return syscall(548, fd, buf, nbytes); }
ssize_t read_crypt(int fd, const void *buf, size_t nbytes) { return syscall(549, fd, buf, nbytes); }

int main() {
	int fd = open("/home/puc/Documentos/fvck.txt", O_RDONLY|O_CREAT, 0666);
	//ssize_t r = syscall(548, fd, "abcde", 5);
	char temp[10];
	ssize_t r = read_crypt(fd, temp, 5);
	printf("Returned %d\n", (int)r);
	printf("Buffer = %s\n", temp);
}

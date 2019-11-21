#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

ssize_t write_crypt(int fd, const void *buf, size_t nbytes) { return syscall(548, fd, buf, nbytes); }
ssize_t read_crypt(int fd, const void *buf, size_t nbytes) { return syscall(549, fd, buf, nbytes); }

int main() {
	int fd = open("/home/puc/Documentos/fvck.txt", O_WRONLY|O_CREAT, 0644);
	ssize_t r = syscall(548, fd, "abcde", 5);
	printf("Returned %d\n", (int)r);
}

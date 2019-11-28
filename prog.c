/*
Bruno Guilherme Spirlandeli Marini         	RA: 17037607
Caio Lima e Souza Della Torre Sanches 		RA: 17225285
Jefferson Meneses da Silva                  	RA: 17230400
Marcos Aurélio Tavares de Sousa Filho 		RA: 17042284
*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define FILE_PATH "/home/puc/Downloads/teste.txt"
#define TESTE_STRUCTS

//(const void *buf, size_t size, size_t count, int fd)
ssize_t write_crypt(int fd, const void *buf, size_t nbytes) { return syscall(548, buf, 1, nbytes, fd); }
ssize_t read_crypt(int fd, const void *buf, size_t nbytes) { return syscall(549, buf, 1, nbytes, fd); }
ssize_t fwrite_crypt(const void *buf, size_t size, size_t count, int fd) { return syscall(548, buf, size, count, fd); }
ssize_t fread_crypt(const void *buf, size_t size, size_t count, int fd) { return syscall(549, buf, size, count, fd); }

struct teste {
	int id;
	char nome[16];
	char ra[9];
	float media;
};

int main() {
	// Teste structs
#ifdef TESTE_STRUCTS
	struct teste alunos_src[3], alunos_dst[3];

	alunos_src[0].id = 0;
	strcpy(alunos_src[0].nome, "aluno 0");
	strcpy(alunos_src[0].ra, "17225285");
	alunos_src[0].media = 9.6;

	alunos_src[1].id = 1;
	strcpy(alunos_src[1].nome, "aluno 1");
	strcpy(alunos_src[1].ra, "54545454");
	alunos_src[1].media = 6.9;

	alunos_src[2].id = 2;
	strcpy(alunos_src[2].nome, "aluno 2");
	strcpy(alunos_src[2].ra, "98764321");
	alunos_src[2].media = 2.2;

	int fd = open(FILE_PATH, O_WRONLY|O_CREAT, 0666);
	ssize_t r = fwrite_crypt(alunos_src, sizeof(struct teste), 3, fd);
	printf("Returned %d\n", (int)r);
	close(fd);

	fd = open(FILE_PATH, O_RDONLY|O_CREAT, 0666);
	r = fread_crypt(alunos_dst, sizeof(struct teste), 3, fd);

	printf("Returned %d\n", (int)r);
	for (int i = 0; i < 3; i++) {
		printf("[%d] RA %s: %s => media %.2f\n", alunos_dst[i].id, alunos_dst[i].ra, alunos_dst[i].nome, alunos_dst[i].media);
	}	
#endif
	// Teste string
#ifdef TESTE_STRING
	char text[100];
	int fd = open(FILE_PATH, O_WRONLY|O_CREAT, 0666);

	printf("Digite um texto [max. 100 carac.]: ");
	scanf("%[^\n]", text);

	ssize_t r = write_crypt(fd,text,strlen(text));
	printf("Returned %d\n", (int)r);

	close(fd);
	fd = open(FILE_PATH, O_RDONLY|O_CREAT, 0666);

	char crypt_rec[1600];
	FILE *fileOp = fopen(FILE_PATH, "r");
	fread(crypt_rec, 1, strlen(text)*16, fileOp);
	printf("Texto armazenado (criptografado): %s", crypt_rec);
	fclose(fileOp);

	char receive[100];

	r = read_crypt(fd,receive,strlen(text));
	receive[strlen(text)] = 0;

	printf("Returned %d\n", (int)r);
	printf("Recebido: %s\n", receive);	
#endif
	return 0;
}

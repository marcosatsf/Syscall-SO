/*
Bruno Guilherme Spirlandeli Marini         	RA: 17037607
Caio Lima e Souza Della Torre Sanches 		RA: 17225285
Jefferson Meneses da Silva                  RA: 17230400
Marcos Aurélio Tavares de Sousa Filho 		RA: 17042284
*/

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 258              // The buffer length including option
unsigned char receive[BUFFER_LENGTH];  // The receive buffer from the LKM

void c2h(char *, char *, int );
char c2h_conv(char);
void h2c(char *, char *, int );
char h2c_conv(char);

int main(){
	
    int ret, fd, opcao, op;
    int nbytes, i;
    int base = 0, pseudo_base, pseudo_top;
    unsigned char c;
    unsigned char *fileContentsHex = "D5AC12AD7294D7244428D996F3259C1CB49085F75432F8D0D38756F37829F7497002E074FA7C9D49DAF9EB0E3C488C97E66A5FCE4518495FD7E77AC453A87728";
    char fileContents[65];
    
    // Convertendo os hexadecimais para binário (economia de espaço em drive + não precisa ser human-readable)
    h2c(fileContentsHex, fileContents, 128);
    
    printf("Convertido => [%s]\n", fileContents);
    
    char stringToSend[BUFFER_LENGTH - 2];
	char send[BUFFER_LENGTH];
	char rcv;

	fd = open("/dev/MyCryptoRomance", O_RDWR);         // Open the device with read/write access
	
	do{
	    printf(" Digite uma quantidade de bytes (valor negativo para sair)\n> ");
		scanf("%d", &nbytes);
        	   
        pseudo_base = 16 * (base / 16);
        pseudo_top = 16 * ((base + nbytes - 1) / 16) + 16;
		if(nbytes > 0){
			
            if (fd < 0){
				perror("FOMOS FALHOS AO ABRIR O DISPOSITIVO...\n");
				printf("Erro cod. %d, %d\n", fd, (int)errno);
				return errno;
		    }
	
		    for(i = pseudo_base; i < pseudo_top; i++)
		    {
		        c = fileContents[i];
		        //printf("C char = %02x\n", c);
			    stringToSend[2 + 2*(i - pseudo_base)]     = c2h_conv(c / (char)16);
			    stringToSend[2 + 2*(i - pseudo_base) + 1] = c2h_conv(c % (char)16);
			    //printf("New chars = %c,%c\n", stringToSend[2 + 2*(i - pseudo_base)], stringToSend[2 + 2*(i - pseudo_base) + 1]);
		    }
		    stringToSend[2 + 2*i] = '\0';
            
		    stringToSend[0] = 'd';
		    stringToSend[1] = ' ';
	
	        printf("[DEBUG] Enviando => '%s'\n", stringToSend);
		//printf("[DEBUG] Enviando =>\n");
		//	for (i = 0; i < nbytes; i++) printf("%c", (char)(h2c_conv(stringToSend[2*i])*16 + h2c_conv(stringToSend[2*i+1])));
	        
		    ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
		    if (ret < 0){
			    perror("Failed to write the message to the device.");
			    return errno;
		    }
	
		    ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
		
		    if (ret < 0){
			    perror("Failed to read the message from the device.");
			    return errno;
		    }
            
            int tamanho_new = 0;
            while (receive[tamanho_new] != 0) tamanho_new++;
            
		    //unsigned char c;

		    printf("Hex:   [");
		    for(int i=0;i<tamanho_new;i++) 
			    printf("%c", receive[i]);
		    printf("]\n");
	
		    tamanho_new /= 2;
		    printf("base = %d, pbase = %d, ptop = %d, pbase mod 16 = %d, diff = %d\n", base, pseudo_base, pseudo_top, pseudo_base % 16, pseudo_top - pseudo_base);
		    printf("ASCII: [");
		    for(int i=0;i<nbytes;i++) 			
			    printf("%c", (char)(h2c_conv(receive[2*(i + base % 16)])*16 + h2c_conv(receive[2*(i + base % 16)+1])));
		    printf("]\n");
	
	        for(int i=0;i<BUFFER_LENGTH;i++) receive[i] = 0;
	        
		    //printf("Press ENTER to return to menu...\n");
		    //getchar();
	
	        base += nbytes;
		    for(int i=0;i<BUFFER_LENGTH -2;i++)stringToSend[i] = 0;
		}
		
	}while(nbytes >= 0);
	
	close(fd);
	
	printf("End of the program\n");
	return 0;
}

void c2h(char *charstrn, char *hexstrn, int charlen) {
	int tam = charlen;
    while (charlen-- >= 0) {
        hexstrn[2*charlen+1] = c2h_conv(charstrn[charlen] % (char)16); //1s
        hexstrn[2*charlen] = c2h_conv(charstrn[charlen] / (char)16);   //16s
    }
	hexstrn[2*tam+2] = 0;
}

char c2h_conv(char c) {
    if (c < (char)10) return c + '0';
    return c + 'A' - (char)10;
}
void h2c(char *hexstrn, char *charstrn, int hexlen) { //Hexlen deve ser par
    hexlen--;
    while (hexlen > 0) {
        charstrn[(int)(hexlen/2)] = h2c_conv(hexstrn[hexlen]) + 16 * h2c_conv(hexstrn[hexlen - 1]);
	    hexlen -= 2;
	}
}

char h2c_conv(char c) {
	if (c <= '9') return c - '0';
    return c - 'A' + (char)10;
}

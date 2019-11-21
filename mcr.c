#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>        // Required for the copy to user function
#include <linux/mutex.h>	  // Required for the mutex functionality
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <crypto/hash.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>

//typedef char char;

#define BLK_SIZE 16
#define AES_KEY_SIZE_BYTES 16

//#define actmalloc(S) malloc(S)
//#define actfree(P) free(P)
//#define actwrite(F, B, S) fwrite(F, B, S)

static char *crp_key = "aaaaaaaaaaaaaaaa";

static void hexdump(unsigned char *, unsigned int);
static int trigger_skcipher_encrypt(char *, int, char *);
static int trigger_skcipher_decrypt(char *, int, char *);

asmlinkage ssize_t sys_write_crypt(int fd, const void *buf, size_t nbytes)
{
	// Vars
	char* cbuf;
	int byte_atual, t;
	char* malocao;
	char* cifrado;
	ssize_t ret;
	mm_segment_t old_fs;
	
	cbuf = (char*)buf;

	pr_info("Params fd=%d, nbytes=%d\n", fd, (int)nbytes);

	// Alloc
	malocao = (char*) vmalloc(nbytes * BLK_SIZE);
	cifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	
	// Fill
	for (byte_atual = 0; byte_atual < nbytes; byte_atual++) {
		malocao[byte_atual * BLK_SIZE] = cbuf[byte_atual];
		for (t = 1; t < BLK_SIZE; t++) malocao[byte_atual * BLK_SIZE + t] = 0; // Fill with garbage maybe
	}
	
	// Encrypt
	trigger_skcipher_encrypt(malocao, nbytes * BLK_SIZE, cifrado);
	
	// Write
	//ret = fwrite(cifrado, 1, nbytes * BLK_SIZE, (FILE *)fd);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_write(fd, cifrado, nbytes * BLK_SIZE);
	set_fs(old_fs);
	
	// Free
	vfree(malocao);
	vfree(cifrado);
        
    return ret;
}


static void hexdump(unsigned char *buf, unsigned int len) {
		unsigned char* aux = buf;
        while (len--) { printk(KERN_CONT "%02x ", *aux); aux++; }
        printk("\n");
}


static int trigger_skcipher_encrypt(char *plaintext, int tam_plaintext, char *cyphertext)
{
    struct crypto_skcipher *skcipher = NULL; // Estrutura contendo o handler de skcipher    
    struct skcipher_request *req = NULL;     // Estrutura contendo o request para o kernel 

    /* Ponteiros para alocar os textos de entrada/saída */
    struct scatterlist sg_scratchpad;
    char *criptograf = NULL;
    struct scatterlist sg_criptograf;
    char *resultdata = NULL;

    /* Ponteiros para alocar o parâmetro de AES */
    char *Ekey = NULL;
    
    int ret = -EFAULT; // Valor de retorno
    int x;             // Variavel contadora

    /* Valores de debug */
    int scratchpad_size;
    
    /* Requisitar uma alocação de cifra */
    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0); //cbc-aes-aesni
    if (IS_ERR(skcipher)) {
        pr_info("Could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
        goto out;
    }

    /* Requisitar uma alocação de requisito para o kernel */
    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    /* Requisitar uma área de memória para alocar a chave */
    Ekey = vmalloc(AES_KEY_SIZE_BYTES);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_KEY_SIZE_BYTES; x++) Ekey[x] = crp_key[x];
    
    /* Configurar chave simétrica */
    if (crypto_skcipher_setkey(skcipher, Ekey, AES_KEY_SIZE_BYTES)) {
        pr_info("Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    scratchpad_size = tam_plaintext;
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    criptograf = vmalloc(scratchpad_size);
    if (!criptograf) {
        pr_info("Could not allocate criptograf\n");
        goto out;
    }
    
    /* Inicializar scatterlists */
    sg_init_one(&sg_scratchpad, plaintext,  scratchpad_size);
    sg_init_one(&sg_criptograf, criptograf, scratchpad_size);
    
    /* Configurar valores da criptografia */
    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_criptograf, scratchpad_size, NULL);
    
    /* Efetuar criptografia */
    ret = crypto_skcipher_encrypt(req);
    
    /* Verificar valor de retorno */
    if (ret) {
        pr_info("Encryption failed...\n");
        goto out;
    }
    
    /* Exibir resultado para debug */
    resultdata = sg_virt(&sg_criptograf);

    printk(KERN_INFO "===== BEGIN RESULT CRYPT =====\n");
    hexdump(resultdata, scratchpad_size);
    printk(KERN_INFO "=====  END RESULT CRYPT  =====");

    /* Armazenar resposta para devolver ao programa */
    for(x=0;x<scratchpad_size;x++) cyphertext[x] = resultdata[x];
    
    /* Liberar estruturas utilizadas */
    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	vfree(Ekey);
    if (criptograf)
        vfree(criptograf);
    return ret;
}

asmlinkage ssize_t sys_read_crypt(int fd, const void *buf, size_t nbytes)
{
	// Vars
	char* cbuf;
	int byte_atual;//, t;
	char* malocao;
	char* decifrado;
	//ssize_t ret;
	mm_segment_t old_fs;
	
	cbuf = (char*)buf;

	pr_info("Params fd=%d, nbytes=%d\n", fd, (int)nbytes);

	// Alloc
	malocao = (char*) vmalloc(nbytes * BLK_SIZE);
	decifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	
	if (fd < 0) return fd;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	sys_read(fd, malocao, nbytes * BLK_SIZE);
	
	// Decrypt
	trigger_skcipher_decrypt(malocao, nbytes * BLK_SIZE, decifrado);
	
	// Fill
	for (byte_atual = 0; byte_atual < nbytes; byte_atual++) {
		cbuf[byte_atual] = decifrado[byte_atual * BLK_SIZE];
	}
	
	// Free
	vfree(malocao);
	vfree(decifrado);
        
    set_fs(old_fs);
    return nbytes;
}

static int trigger_skcipher_decrypt(char *cyphertext, int tam_plaintext, char *plaintext)
{
    struct crypto_skcipher *skcipher = NULL; // Estrutura contendo o handler de skcipher    
    struct skcipher_request *req = NULL;     // Estrutura contendo o request para o kernel 

    /* Ponteiros para alocar os textos de entrada/saída */
    struct scatterlist sg_scratchpad;
    char *decriptogr = NULL;
    struct scatterlist sg_decriptogr;
    char *resultdata = NULL;

    /* Ponteiros para alocar o parâmetro de AES */
    char *Ekey = NULL;
    
    int ret = -EFAULT; // Valor de retorno
    int x;             // Variavel contadora

    /* Valores de debug */
    int scratchpad_size;
    
    /* Requisitar uma alocação de cifra */
    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0); //cbc-aes-aesni
    if (IS_ERR(skcipher)) {
        pr_info("Could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
        goto out;
    }

    /* Requisitar uma alocação de requisito para o kernel */
    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    /* Requisitar uma área de memória para alocar a chave */
    Ekey = vmalloc(AES_KEY_SIZE_BYTES);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_KEY_SIZE_BYTES; x++) Ekey[x] = crp_key[x];
    
    /* Configurar chave simétrica */
    if (crypto_skcipher_setkey(skcipher, Ekey, AES_KEY_SIZE_BYTES)) {
        pr_info("Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    scratchpad_size = tam_plaintext;
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    decriptogr = vmalloc(scratchpad_size);
    if (!decriptogr) {
        pr_info("Could not allocate criptograf\n");
        goto out;
    }
    
    /* Inicializar scatterlists */
    sg_init_one(&sg_scratchpad, cyphertext, scratchpad_size);
    sg_init_one(&sg_decriptogr, decriptogr, scratchpad_size);
    
    /* Configurar valores da criptografia */
    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_decriptogr, scratchpad_size, NULL);
    
    /* Efetuar criptografia */
    ret = crypto_skcipher_decrypt(req);
    
    /* Verificar valor de retorno */
    if (ret) {
        pr_info("Decryption failed...\n");
        goto out;
    }
    
    /* Exibir resultado para debug */
    resultdata = sg_virt(&sg_decriptogr);

    printk(KERN_INFO "===== BEGIN RESULT DECRYPT =====\n");
    hexdump(resultdata, scratchpad_size);
    printk(KERN_INFO "=====  END RESULT DECRYPT  =====");

    /* Armazenar resposta para devolver ao programa */
    for(x=0;x<scratchpad_size;x++) plaintext[x] = resultdata[x];
    
    /* Liberar estruturas utilizadas */
    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	vfree(Ekey);
    if (decriptogr)
        vfree(decriptogr);
    return ret;
}

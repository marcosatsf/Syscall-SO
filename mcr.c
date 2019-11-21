//#include <asm/uaccess.h>

#include <crypto/hash.h>
#include <crypto/skcipher.h>

#include <linux/crypto.h>
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/mm.h>
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/moduleparam.h>
#include <linux/mutex.h>	  // Required for the mutex functionality
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>        // Required for the copy to user function
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#define BLK_SIZE 16
#define AES_KEY_SIZE_BYTES 16

static char *crp_key = "aaaaaaaaaaaaaaaa";

enum cipher_mode { encrypt=0, decrypt };

static void hexdump(unsigned char *, unsigned int);
static int trigger_skcipher(char *, int, char *, enum cipher_mode);
/*
static int trigger_skcipher_encrypt(char *, int, char *);
static int trigger_skcipher_decrypt(char *, int, char *);
*/

asmlinkage ssize_t sys_write_crypt(int fd, const void *buf, size_t nbytes)
{
	// Vars
	char* cbuf;
	int byte_atual, t;
	char* decifrado;
	char* cifrado;
	ssize_t ret;
	mm_segment_t old_fs;
	int cipher_res;
	
	cbuf = (char*)buf;

	pr_info("Params fd=%d, nbytes=%d\n", fd, (int)nbytes);

	// Alloc
	decifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	cifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	
	// Fill
	for (byte_atual = 0; byte_atual < nbytes; byte_atual++) {
		decifrado[byte_atual * BLK_SIZE] = cbuf[byte_atual];
		for (t = 1; t < BLK_SIZE; t++) decifrado[byte_atual * BLK_SIZE + t] = 0; // Fill with garbage maybe
	}
	
	// Encrypt
	cipher_res = trigger_skcipher(decifrado, nbytes * BLK_SIZE, cifrado, encrypt);
	if (cipher_res) { ret = cipher_res; goto out_write; }
	//trigger_skcipher_encrypt(malocao, nbytes * BLK_SIZE, cifrado);
	
	// Write
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_write(fd, cifrado, nbytes * BLK_SIZE);
	set_fs(old_fs);
	
out_write:
	// Free
	vfree(decifrado);
	vfree(cifrado);
        
    return ret;
}

asmlinkage ssize_t sys_read_crypt(int fd, const void *buf, size_t nbytes)
{
	// Vars
	char* cbuf;
	int byte_atual;//, t;
	char* cifrado;
	char* decifrado;
	ssize_t ret;
	mm_segment_t old_fs;
	int cipher_res;
	
	cbuf = (char*)buf;

	pr_info("Params fd=%d, nbytes=%d\n", fd, (int)nbytes);

	// Alloc
	cifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	decifrado = (char*) vmalloc(nbytes * BLK_SIZE);
	
	if (fd < 0) return fd;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	sys_read(fd, cifrado, nbytes * BLK_SIZE);
	
	// Decrypt
	cipher_res = trigger_skcipher(decifrado, nbytes * BLK_SIZE, cifrado, decrypt);
	if (cipher_res) { ret = cipher_res; goto out_read; }
	//trigger_skcipher_decrypt(malocao, nbytes * BLK_SIZE, decifrado);
	
	// Fill
	for (byte_atual = 0; byte_atual < nbytes; byte_atual++) {
		cbuf[byte_atual] = decifrado[byte_atual * BLK_SIZE];
	}
	ret = nbytes;
	
out_read:
	// Free
	vfree(cifrado);
	vfree(decifrado);
        
    set_fs(old_fs);
    return ret;
}

static void hexdump(unsigned char *buf, unsigned int len) {
		unsigned char* aux = buf;
        while (len--) { printk(KERN_CONT "0x%02x ", *aux); aux++; }
        printk("\n");
}

static int trigger_skcipher(char *plaintext, int size, char *cyphertext, enum cipher_mode mode)
{
    struct crypto_skcipher *skcipher = NULL; // Estrutura contendo o handler de skcipher    
    struct skcipher_request *req = NULL;     // Estrutura contendo o request para o kernel 

    /* Ponteiros para alocar os textos de entrada/saída */
    struct scatterlist sg_plain;
    struct scatterlist sg_crypt;
    char *crypt_res = NULL;
    char *resultdata = NULL;
    
    /* Ponteiros para alocar o parâmetro de AES */
    char *Ekey = NULL;
    
    int ret = -EFAULT; // Valor de retorno
    int x;             // Variavel contadora
    
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
    
    /* Requisitar uma área de memória para alocar o resultado do processo */
    crypt_res = vmalloc(size);
    if (!crypt_res) {
        pr_info("Could not allocate criptograf\n");
        goto out;
    }
    
    if (mode == encrypt) {
        /* Inicializar scatterlists */
        sg_init_one(&sg_plain, plaintext, size);
        sg_init_one(&sg_crypt, crypt_res, size);
        
        /* Configurar valores da criptografia */
        skcipher_request_set_crypt(req, &sg_plain, &sg_crypt, size, NULL);
        
        /* Efetuar criptografia */
    	ret = crypto_skcipher_encrypt(req);
	} else if (mode == decrypt) {
        /* Inicializar scatterlists */
        sg_init_one(&sg_plain, crypt_res,  size);
        sg_init_one(&sg_crypt, cyphertext, size);
        
        /* Configurar valores da criptografia */
        skcipher_request_set_crypt(req, &sg_crypt, &sg_plain, size, NULL);
        
        /* Efetuar criptografia */
    	ret = crypto_skcipher_decrypt(req);
	} else {
		ret = -1;
	}
    
    /* Verificar valor de retorno */
    if (ret) {
        pr_info("Encryption failed...\n");
        goto out;
    }
    
    /* Exibir resultado para debug */
    if (mode == encrypt) {
        resultdata = sg_virt(&sg_crypt);
	} else if (mode == decrypt) {
        resultdata = sg_virt(&sg_plain);
	}

    printk(KERN_INFO "===== BEGIN RESULT =====\n");
    hexdump(resultdata, size);
    printk(KERN_INFO "=====  END RESULT  =====\n");

    /* Exibir resultado para debug */
    if (mode == encrypt) {
        for(x=0;x<size;x++) cyphertext[x] = resultdata[x];
	} else if (mode == decrypt) {
        for(x=0;x<size;x++) plaintext[x] = resultdata[x];
	}
    
    /* Liberar estruturas utilizadas */
    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	vfree(Ekey);
    if (crypt_res)
        vfree(crypt_res);
        
    return ret;
}


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

asmlinkage ssize_t sys_write_crypt(const void *buf, size_t size, size_t count, int fd)
{
	// Vars
	char* cbuf;
	int byte_atual;
	char* decifrado;
	char* cifrado;
	ssize_t ret;
	mm_segment_t old_fs;
	int cipher_res;
	size_t eff_blocksize;
	int buffer_offset;
	
	ret = 0;
	buffer_offset = 0;
	cbuf = (char*)buf;
	eff_blocksize = BLK_SIZE * ((size - 1) / BLK_SIZE) + BLK_SIZE; // Smallest BLK_SIZE-sized area to fit "size_t size"

	pr_info("Params fd=%d, size=%d, count=%d\n", fd, (int)size, (int)count);

	if (fd < 0) return fd;
	if (size <= 0) return size;
	if (count <= 0) return count;
	
    old_fs = get_fs();
    set_fs(KERNEL_DS);
	
	// Alloc
	cifrado = NULL;
	decifrado = (char*) vmalloc(eff_blocksize);
	if (decifrado == NULL) goto out;
	cifrado = (char*) vmalloc(eff_blocksize);
	if (cifrado == NULL) goto out;
    
	while (count) {
	    // Fill
	    for (byte_atual = 0; byte_atual < size;          byte_atual++) decifrado[byte_atual] = cbuf[byte_atual + buffer_offset];
	    for (;               byte_atual < eff_blocksize; byte_atual++) decifrado[byte_atual] = 0; //Padding (maybe fill with garbage)
	    
	    // Encrypt
	    cipher_res = trigger_skcipher(decifrado, eff_blocksize, cifrado, encrypt);
	    if (cipher_res) { goto out; }
	    
	    // Write
	    ret += sys_write(fd, cifrado, eff_blocksize);
	    
	    // Decrement
	    count--;
	    buffer_offset += size;
	}
	
out:
	// Free
	if (cifrado != NULL) vfree(cifrado);
	if (decifrado != NULL) vfree(decifrado);
        
    set_fs(old_fs);
    return ret;
}

asmlinkage ssize_t sys_read_crypt(void *buf, size_t size, size_t count, int fd)
{
	// Vars
	char* cbuf;
	int byte_atual;
	char* cifrado;
	char* decifrado;
	ssize_t ret, thisret;
	mm_segment_t old_fs;
	int cipher_res;
	int buffer_offset;
	size_t eff_blocksize;
	
	ret = 0;
	buffer_offset = 0;
	cbuf = (char*)buf;
	eff_blocksize = BLK_SIZE * ((size - 1) / BLK_SIZE) + BLK_SIZE; // Smallest BLK_SIZE-sized area to fit "size_t size"

	pr_info("Params fd=%d, size=%d, count=%d\n", fd, (int)size, (int)count);
	
	if (fd < 0) return fd;
	if (size <= 0) return size;
	if (count <= 0) return count;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	// Alloc
	decifrado = NULL;
	cifrado = (char*) vmalloc(eff_blocksize);
	if (cifrado == NULL) goto out;
	decifrado = (char*) vmalloc(eff_blocksize);
	if (decifrado == NULL) goto out;
    
	while (count) {
        // Read from file
        thisret = sys_read(fd, cifrado, eff_blocksize);
        if (thisret < eff_blocksize) { pr_info("Found incomplete block..."); goto out; }
        
	    // Decrypt
	    cipher_res = trigger_skcipher(decifrado, eff_blocksize, cifrado, decrypt);
	    if (cipher_res) { goto out; }
	    
	    // Fill
	    for (byte_atual = 0; byte_atual < size; byte_atual++) cbuf[byte_atual + buffer_offset] = decifrado[byte_atual];
	    
	    // Decrement
	    count--;
	    
	    // Increase offset (compensate for padding)
	    buffer_offset += size;
	    ret += thisret;
	}
	
out:
	// Free
	if (cifrado != NULL) vfree(cifrado);
	if (decifrado != NULL) vfree(decifrado);
        
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


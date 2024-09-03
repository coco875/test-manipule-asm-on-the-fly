/* test1.c */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

// separate assembly instructions by ; or \n
#define CODE "CALL 0"

void hook_add(void);

int add(int a, int b) {
    return a+b;
}

void hook_add(void) {
    printf("hello world\n");
}

void unprotect_memory(void * addr, size_t size) {
    int pagesize = sysconf(_SC_PAGE_SIZE);
    uint64_t ptr = ((uint64_t) addr) & (~(pagesize-1));
    size += ((uint64_t) addr)-ptr;
    int n = size/pagesize;
    if (mprotect((void *) ptr, (n+1)*pagesize, PROT_WRITE|PROT_READ|PROT_EXEC) != 0) {
        printf("error %d %lx\n", errno, ptr);
        switch (errno) {
            case EACCES:
            printf("L'accès spécifié n'est pas possible sur ce type de mémoire. Ceci se produit par exemple si vous utilisez mmap(2) pour représenter un fichier en lecture seule en mémoire, et si vous demandez de marquer cette zone avec PROT_WRITE.\n");
            break;
            case EFAULT:
            printf("La mémoire n'est pas accessible.\n");
            break;
            case EINVAL:
            printf("addr n'est pas un pointeur valide, ou ce n'est pas un multiple de la taille de page du système.\n");
            break;
            case ENOMEM:
            printf("Impossible d'allouer les structures nécessaires dans le noyau. Pas assez de mémoire pour le noyau. Ou : les adresses de l'intervalle [addr, addr+len] ne sont pas valides dans l'espace d'adressage du processus, ou spécifient une ou plusieurs pages qui ne sont pas projetées.\n");
            break;
        }
        exit(-1);
    }
}

void convert_asm(ks_engine *ks, char *code, uint64_t address, unsigned char **encode, size_t *size, size_t *count) {
    if (ks_asm(ks, code, address, encode, size, count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
		         count, ks_errno(ks));
        // NOTE: free encode after usage to avoid leaking memory
        ks_free(*encode);

        // close Keystone instance when done
        ks_close(ks);
        exit(-1);
    }
    size_t i;

    printf("%s = ", code);
    for (i = 0; i < *size; i++) {
        printf("%02x ", (*encode)[i]);
    }
    printf("\n");
    printf("Compiled: %lu bytes, statements: %lu\n", *size, *count);
}

int main(void) {   
    // capstone
	csh handle;
	cs_insn *insn;

    // keystone
    ks_engine *ks;

    // data
    unsigned char *encode;
    size_t size;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
    
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        return -1;

	count = cs_disasm(handle, (void*) &add, 30, (uint64_t) (void*) &add, 0, &insn);
	if (count <= 0) {
		printf("ERROR: Failed to disassemble given code!\n");
        cs_close(&handle);
        exit(-1);
    }
    size_t j;
    for (j = 0; j < count; j++) {
        printf("0x%"PRIx64":\tsize:%ld\t%s\t\t%s\n", insn[j].address, insn[j].size, insn[j].mnemonic,
                insn[j].op_str);
    }

    char code[1024];
    size_t size_function = 4096;
    void *lambda_function = malloc(size_function);
    sprintf(code, "jmp %ld", lambda_function);
    convert_asm(ks, code, (uint64_t) add, &encode, &size, &count);

    unprotect_memory(&add, size);
    memcpy(&add, encode, size);

    void *original_function = malloc(size_function);

    sprintf(code, "");

    size_t size_junk = 0;
    int i = 0;
    while (size>size_junk) {
        sprintf(code,"%s %s %s;", code, insn[i].mnemonic, insn[i].op_str);
        size_junk += insn[i].size;
        i++;
    }

    sprintf(code, "%s jmp 0x%lx;", code, insn[i].address);
    convert_asm(ks, code, (uint64_t) original_function, &encode, &size, &count);

    unprotect_memory(original_function, size);
    memcpy(original_function, encode, size);
    
    sprintf(code, "call 0x%lx; ret;", original_function);
    convert_asm(ks, code, (uint64_t) lambda_function, &encode, &size, &count);

    unprotect_memory(lambda_function, size);
    memcpy(lambda_function, encode, size);

    printf("add result %d\n", add(10,10));
    
    cs_close(&handle);

    cs_free(insn, count);

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

int replace_hook(int a, int b) {
    hook_add();
    return add(a,b);
}

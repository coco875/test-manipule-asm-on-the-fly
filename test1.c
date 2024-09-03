/* test1.c */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

// separate assembly instructions by ; or \n
#define CODE "CALL 0"

void hook_add(void);

int add(int a, int b) {
    return a+b;
}

void fakememcpy(void * dest, void * src, size_t size) {
    printf("copy %lx from %lx\n", dest, src);
    unsigned char *out = (unsigned char *)dest;
    unsigned char *in = (unsigned char *) src;
    for (int i = 0; i<size; i++) {
        printf("copy %02x to %lx\n", in[i], &out[i]);
        out[i] = in[i];
    }
}

int main(void)
{   
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
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
    }

	cs_close(&handle);

    char code[1024];
    sprintf(code, "jmp %ld", &add);

    if (ks_asm(ks, code, (uint64_t) (void*) &add, &encode, &size, &count) != KS_ERR_OK) {
          printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
		         count, ks_errno(ks));
    } else {
        size_t i;

        printf("%s = ", code);
        for (i = 0; i < size; i++) {
            printf("%02x ", encode[i]);
        }
        printf("\n");
        printf("Compiled: %lu bytes, statements: %lu\n", size, count);
    }
    // if (mprotect(&add, size, PROT_WRITE) != 0) {
    //     printf("error %d %ld\n", errno, &add);
    //     switch (errno) {
    //         case EACCES:
    //         printf("L'accès spécifié n'est pas possible sur ce type de mémoire. Ceci se produit par exemple si vous utilisez mmap(2) pour représenter un fichier en lecture seule en mémoire, et si vous demandez de marquer cette zone avec PROT_WRITE.\n");
    //         break;
    //         case EFAULT:
    //         printf("La mémoire n'est pas accessible.\n");
    //         break;
    //         case EINVAL:
    //         printf("addr n'est pas un pointeur valide, ou ce n'est pas un multiple de la taille de page du système.\n");
    //         break;
    //         case ENOMEM:
    //         printf("Impossible d'allouer les structures nécessaires dans le noyau. Pas assez de mémoire pour le noyau. Ou : les adresses de l'intervalle [addr, addr+len] ne sont pas valides dans l'espace d'adressage du processus, ou spécifient une ou plusieurs pages qui ne sont pas projetées.\n");
    //         break;
    //     }
    //     return -1;
    // }
    fakememcpy(&add, encode, size);
  
    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

void hook_add(void) {
    printf("hello world\n");
    asm(
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
    );
}

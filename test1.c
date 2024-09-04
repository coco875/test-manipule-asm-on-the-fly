/* test1.c */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

char *register_64[] = {
    "rdi",
    "rsi",
    "rdx",
    "rcx",
    "r8",
    "r9"
};

char *register_32[] = {
    "edi",
    "esi",
    "edx",
    "ecx",
    "r8d",
    "r9d"
};

char **registre_name[] = {
    register_32,
    register_64
};

int add(int a, int b) {
    return a+b;
}

void hook1_add(void) {
    printf("hello world 1\n");
}

void hook2_add(void) {
    printf("hello world 2\n");
}

int around_power_2(int a) {
    int i;
    for(i = 1; i<=a; i=i<<1) {}
    return i;
}

typedef struct Hook_ {
    void* func;
    struct Hook_* next;
} Hook;

typedef struct FuncHook_ {
    void* func;
    char* type;
    int num_arg;
    int size_stack;
    struct FuncHook_* next;
    Hook* hook_list;
} FuncHook;

FuncHook* list_hook = NULL;

void register_func_hook(csh *handle, void * func, char *type, int num_arg) {
    FuncHook** it = &list_hook;
    while (*it!=NULL) {
        it = &((*it)->next);
    }
    *it = malloc(sizeof(FuncHook));
    (*it)->func = func;
    (*it)->type = malloc(sizeof(char)*num_arg);
    memcpy((*it)->type, type, num_arg);
    (*it)->num_arg = num_arg;
    (*it)->size_stack = 0;
    for (int i = 0; i<(*it)->num_arg; i++) {
        (*it)->size_stack += ((*it)->type[i]+1)*4;
    }
    (*it)->size_stack = around_power_2((*it)->size_stack);
    size_t count = cs_disasm(*handle, func, 30, (uint64_t) func, 0, &insn);
	if (count <= 0) {
		printf("ERROR: Failed to disassemble given code!\n");
        cs_close(handle);
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
    ks_free(encode);

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
    ks_free(encode);
}

void inject(void* hook, void* func) {
    FuncHook** it = &list_hook;
    while (*it!=NULL && (*it)->func==func) {
        it = &((*it)->next);
    }
    if (*it == NULL) {
        printf("Cannot hook an unregister function \n");
        exit(-1);
    }
    Hook** hook_it = (*it)->hook_list;
    while (*hook_it!=NULL) {
        hook_it = &((*hook_it)->next);
    }
    *hook_it = malloc(sizeof(Hook));
    (*hook_it)->func = func;
}

void register_hook(void) {
    char add_type[] = {0, 0};
    register_type_hook(add, add_type, 2);
    inject(hook1_add, add);
    inject(hook2_add, add);
}

void apply_hook(void) {
    char code_buffer[4096];
    FuncHook** it = &list_hook;
    while (*it!=NULL) {
        sprintf(code_buffer, "push rbp; mov	rbp, rsp; sub rsp, %d;\n", (*it)->size_stack);
        int size_stack = 0;
        for (int i = 0; i<(*it)->num_arg; i++) {
            size_stack+=(((*it)->type[i]+1)*4);
            sprintf(code_buffer, "%s mov DWORD PTR [rbp-%d], %s;\n", code_buffer, size_stack, registre_name[(*it)->type[i]][i]);
        }
        
        Hook** hook_it = (*it)->hook_list;
        while (*hook_it!=NULL) {
            sprintf(code_buffer, "%s call 0x%lx;\n", code_buffer, (*hook_it)->func);
            hook_it = &((*hook_it)->next);
        }

        size_stack = 0;
        for (int i = 0; i<(*it)->num_arg; i++) {
            size_stack+=(((*it)->type[i]+1)*4);
            sprintf(code_buffer, "%s mov %s, DWORD PTR [rbp-%d];\n", code_buffer, registre_name[(*it)->type[i]][i], size_stack);
        }
        it = &((*it)->next);
    }
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
        printf("ERROR: ks_asm() failed & count = %ln, error = %u\n",
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

    register_hook();

    printf("add result %d\n", add(10,10));
    
    cs_close(&handle);

    cs_free(insn, count);

    // NOTE: free encode after usage to avoid leaking memory
    // ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

int replace_hook(int a, int b) {
    hook1_add();
    return add(a,b);
}

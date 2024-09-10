/* test1.c */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "vec.h"

char* register_64[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };

char* register_32[] = { "edi", "esi", "edx", "ecx", "r8d", "r9d" };

char* return_register[] = { "eax", "rax" };

char** registre_name[] = { register_32, register_64 };

int add(int a, int b) {
    return a + b;
}

void hook1_add(int a) {
    printf("hello world 1, a:%d\n", a);
}

void hook2_add(int a, int b, bool* cancel) {
    printf("hello world 2, a:%d b:%d\n", a, b);
}

int around_power_2(int a) {
    int i;
    for (i = 1; i <= a; i = i << 1) {}
    return i;
}

void unprotect_memory(void* addr, size_t size) {
    int pagesize = sysconf(_SC_PAGE_SIZE);
    uintptr_t ptr = ((uintptr_t) addr) & (~(pagesize - 1));
    size += ((uintptr_t) addr) - ptr;
    int n = size / pagesize;

    if (mprotect((void*) ptr, (n + 1) * pagesize, PROT_WRITE | PROT_READ | PROT_EXEC) != 0) {
        printf("error %d %lx\n", errno, ptr);
        switch (errno) {
            case EACCES:
                printf("L'accès spécifié n'est pas possible sur ce type de mémoire. Ceci "
                       "se produit par exemple si vous utilisez mmap(2) pour représenter "
                       "un fichier en lecture seule en mémoire, et si vous demandez de "
                       "marquer cette zone avec PROT_WRITE.\n");
                break;
            case EFAULT:
                printf("La mémoire n'est pas accessible.\n");
                break;
            case EINVAL:
                printf("addr n'est pas un pointeur valide, ou ce n'est pas un multiple "
                       "de la taille de page du système.\n");
                break;
            case ENOMEM:
                printf("Impossible d'allouer les structures nécessaires dans le noyau. "
                       "Pas assez de mémoire pour le noyau. Ou : les adresses de "
                       "l'intervalle [addr, addr+len] ne sont pas valides dans l'espace "
                       "d'adressage du processus, ou spécifient une ou plusieurs pages "
                       "qui ne sont pas projetées.\n");
                break;
        }
        exit(-1);
    }
}

void insert_asm(ks_engine* ks, char* code, void* address, size_t* size) {
    unsigned char* encode;
    size_t count;
    if (ks_asm(ks, code, (uintptr_t) address, &encode, size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %zu, error = %u\n", count, ks_errno(ks));
        // NOTE: free encode after usage to avoid leaking memory
        ks_free(encode);

        // close Keystone instance when done
        ks_close(ks);
        exit(-1);
    }
    size_t i;

    printf("%s = ", code);
    for (i = 0; i < *size; i++) {
        printf("%02x ", encode[i]);
    }
    printf("\n");
    printf("Compiled: %lu bytes, statements: %lu\n", *size, count);

    unprotect_memory(address, *size);
    memcpy(address, encode, *size);
    ks_free(encode);
}

enum TypeRegister { NO_REG = 0, _32_BITS, _64_BITS };
enum PositionHook { HEAD, RETURN };

typedef struct {
    enum PositionHook position;
} HookTarget;

typedef struct {
    void* func;
    int num_arg;
    HookTarget target;
    bool cancellable;
} Hook;

typedef struct {
    int lenght;
    int max_lenght;
    Hook** list;
} Vec_Hook;

typedef struct {
    void* func;
    enum TypeRegister* type;
    int num_arg;
    enum TypeRegister return_type;
    int size_stack;
    bool can_be_cancel;
    void* original_func;
    void* hook_function;
    Vec_Hook* hook_list;
} FuncHook;

typedef struct {
    int lenght;
    int max_lenght;
    FuncHook** list;
} Vec_FuncHook;

Vec_FuncHook list_hook = { 0, 0, NULL };

void register_func_hook(csh* handle, ks_engine* ks, void* func, enum TypeRegister* type, int num_arg,
                        enum TypeRegister return_type) {
    cs_insn* insn;
    size_t size;
    FuncHook* it = malloc(sizeof(FuncHook));
    append_vec((Vec*) &list_hook, it);
    it->func = func;
    it->type = malloc(sizeof(char) * num_arg);
    memcpy(it->type, type, num_arg * sizeof(enum TypeRegister));
    it->num_arg = num_arg;
    it->return_type = return_type;
    it->size_stack = 0;
    it->hook_list = (Vec_Hook*) create_vec();

    for (int i = 0; i < it->num_arg; i++) {
        it->size_stack += it->type[i] * 4;
        printf("size_stack:%d\n", it->size_stack);
    }

    it->size_stack += return_type * 4;
    printf("size_stack:%d\n", it->size_stack);

    size_t count = cs_disasm(*handle, func, 1024, (uint64_t) func, 0, &insn);

    if (count <= 0) {
        printf("ERROR: Failed to disassemble given code!\n");
        cs_close(handle);
        exit(-1);
    }

    char code[1024];
    size_t size_function = 4096;
    it->hook_function = malloc(size_function);
    sprintf(code, "jmp 0x%lx", (uintptr_t) it->hook_function);
    insert_asm(ks, code, (void*) func, &size);

    sprintf(code, "");

    size_t size_junk = 0;

    int i;
    for (i = 0; i < count && size > size_junk; i++) {
        printf("0x%" PRIx64 ":\tsize:%hu\t%s\t\t%s\n", insn[i].address, insn[i].size, insn[i].mnemonic, insn[i].op_str);
        sprintf(code, "%s %s %s;", code, insn[i].mnemonic, insn[i].op_str);
        size_junk += insn[i].size;
    }

    uintptr_t ptr = (uintptr_t) malloc(size_function);
    it->original_func = (void*) ptr;

    sprintf(code, "%s jmp 0x%lx;", code, insn[i].address);
    insert_asm(ks, code, (void*) it->original_func, &size);

    cs_free(insn, count);
}

bool compare(void* func, void* func_hook) {
    FuncHook* element = (FuncHook*) func_hook;
    return element->func == func;
}

void inject(Hook hook, void* func) {
    FuncHook* it = find_vec((Vec*) &list_hook, func, compare);
    if (it == NULL) {
        printf("Cannot hook an unregister function \n");
        exit(-1);
    }
    if (hook.cancellable && !it->can_be_cancel) {
        it->can_be_cancel = true;
        it->size_stack += 1;
    }

    Hook* hook_it = malloc(sizeof(Hook));
    append_vec((Vec*) it->hook_list, hook_it);
    memcpy(hook_it, &hook, sizeof(Hook));
}

void register_hook(csh* handle, ks_engine* ks) {
    enum TypeRegister add_type[] = { _32_BITS, _32_BITS };
    register_func_hook(handle, ks, add, add_type, 2, _32_BITS);
    inject((Hook){ .func = hook1_add, .num_arg = 1, .target = { .position = RETURN } }, add);
    inject((Hook){ .func = hook2_add, .num_arg = 3, .cancellable = true }, add);
}

void write_asm_arg_load(char* code, enum TypeRegister* type, int num_arg) {
    size_t size_stack = 0;
    for (int i = 0; i < num_arg; i++) {
        size_stack += type[i] * 4;
        sprintf(code, "%s mov %s, DWORD PTR [rbp - %zu];\n", code, registre_name[(int) type[i] - 1][i], size_stack);
    }
}

void apply_hook(ks_engine* ks) {
    char code_buffer[4096];
    size_t size;
    for (int i = 0; i < list_hook.lenght; i++) {
        print_vec((Vec*) &list_hook);
        FuncHook* it = get_vec((Vec*) &list_hook, i);
        sprintf(code_buffer, "push rbp; mov rbp, rsp; sub rsp, %d;\n", around_power_2(it->size_stack));
        int size_stack = 0;
        for (int j = 0; j < it->num_arg; j++) {
            size_stack += it->type[j] * 4;
            sprintf(code_buffer, "%s mov DWORD PTR [rbp - %d], %s;\n", code_buffer, size_stack,
                    registre_name[(int) it->type[j] - 1][j]);
        }

        size_stack += it->return_type * 4;

        Vec_Hook* hook_list = it->hook_list;
        for (int j = 0; j < hook_list->lenght; j++) {
            Hook* hook_it = get_vec((Vec*) hook_list, j);
            if (hook_it->target.position != HEAD) {
                continue;
            }
            write_asm_arg_load(code_buffer, it->type, hook_it->num_arg);
            sprintf(code_buffer, "%s call 0x%lx;\n", code_buffer, (uintptr_t) hook_it->func);
        }

        write_asm_arg_load(code_buffer, it->type, it->num_arg);
        sprintf(code_buffer, "%s call 0x%lx;\n", code_buffer, (uintptr_t) it->original_func);

        if (it->return_type != NO_REG) {
            sprintf(code_buffer, "%s mov DWORD PTR [rbp - %d], %s;\n", code_buffer, size_stack,
                    return_register[it->return_type - 1]);
        }

        hook_list = it->hook_list;
        for (int j = 0; j < hook_list->lenght; j++) {
            Hook* hook_it = get_vec((Vec*) hook_list, j);
            if (hook_it->target.position != RETURN) {
                continue;
            }
            write_asm_arg_load(code_buffer, it->type, hook_it->num_arg);
            sprintf(code_buffer, "%s call 0x%lx;\n", code_buffer, (uintptr_t) hook_it->func);
        }

        if (it->return_type != NO_REG) {
            sprintf(code_buffer, "%s mov %s, DWORD PTR [rbp - %d];\n", code_buffer,
                    return_register[it->return_type - 1], size_stack);
        }

        sprintf(code_buffer, "%s leave; ret;\n", code_buffer);
        insert_asm(ks, code_buffer, (void*) it->hook_function, &size);
    }
    printf("finish apply hook\n");
}

int main(void) {
    // capstone
    csh handle;

    // keystone
    ks_engine* ks;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        return -1;

    register_hook(&handle, ks);
    apply_hook(ks);

    printf("add result %d\n", add(10, 10));

    cs_close(&handle);

    // NOTE: free encode after usage to avoid leaking memory
    // ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

int replace_hook(int a, int b) {
    bool cancel = false;
    hook2_add(a, b, &cancel);
    if (cancel)
        return 0;
    int c = add(a, b);
    hook1_add(a);
    return c;
}

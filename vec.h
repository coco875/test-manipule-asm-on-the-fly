#include <stdbool.h>

typedef struct {
    int lenght;
    int max_lenght;
    void** list;
} Vec;

Vec* create_vec();
void extend_vec(Vec*);
void set_vec(Vec*, void*, int);
void* get_vec(Vec*, int);
void append_vec(Vec*, void*);
void* remove_vec(Vec*, int);
void* pop_vec(Vec*);
void* find_vec(Vec*, void*, bool (*func)(void*, void*));
void iter_vec(Vec*, void (*func)(void*));
void print_vec(Vec*);

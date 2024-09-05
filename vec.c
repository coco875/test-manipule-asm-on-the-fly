#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    int lenght;
    int max_lenght;
    void **list;
} Vec;

Vec *create_vec() {
    Vec* vec = malloc(sizeof(Vec));
    vec->lenght = 0;
    vec->max_lenght = 0;
    vec->list = NULL;
    return vec;
}

void extend_vec(Vec* vec) {
    vec->max_lenght = vec->max_lenght == 0 ? 1 : vec->max_lenght<<1;
    void ** new_list = malloc(sizeof(void*)*vec->max_lenght);
    if (vec->list!=NULL) {
        memcpy(new_list, vec->list, sizeof(void*)*vec->lenght);
        free(vec->list);
    }
    vec->list = new_list;
}

void set_vec(Vec* vec, void *element, int index) {
    assert(vec->lenght > index && index >0);
    vec->list[index] = element;
}

void* get_vec(Vec* vec, int index) {
    assert(vec->lenght > index && index >0);
    return vec->list[index];
}

void append_vec(Vec* vec, void *element) {
    if (vec->max_lenght == vec->lenght) {
        extend_vec(vec);
    }
    vec->list[vec->lenght] = element;
    vec->lenght++;
}

void* remove_vec(Vec* vec, int index) {
    assert(vec->lenght > index && index >0);
    void* element = vec->list[index];
    memcpy(vec->list[index], vec->list[index+1], index-vec->lenght-1);
    return element;
}

void* pop_vec(Vec* vec) {
    void* element = vec->list[vec->lenght-1];
    vec->list[vec->lenght-1] = NULL;
    vec->lenght--;
    return element;
}

void* find_vec(Vec* vec, void* element, bool (*func) (void*, void*)) {
    for (int i=0; i<vec->lenght; i++) {
        if (func(element, vec->list[i])) {
            return vec->list[i];
        }
    }
    return NULL;
}
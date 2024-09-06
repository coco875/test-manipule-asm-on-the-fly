#include <string.h>

typedef float Vec3f[3];

struct Actor {
    int id;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
};

struct ActorRegistry {
    void (*init) (struct Actor*);
    void (*render) (struct Actor*);
    void (*update) (struct Actor*);
};

struct ActorRegistry gActorRegistry[1024] = {};
int gActorRegistrySize = 0;

int register_actor(struct ActorRegistry actor_register) {
    int id = gActorRegistrySize;
    memcpy(&gActorRegistry[id], &actor_register, sizeof(struct ActorRegistry));
    gActorRegistrySize++;
    return id;
}

struct Actor gActorList[1024] = {};
int gActorListSize = 0;

void spawn_actor(int id, Vec3f position, Vec3f velocity, Vec3f rotation) {
    struct Actor *actor = &gActorList[gActorListSize];
    actor->id = id;
    memcpy(actor->position, position, sizeof(Vec3f));
    memcpy(actor->velocity, velocity, sizeof(Vec3f));
    memcpy(actor->rotation, rotation, sizeof(Vec3f));
    if (gActorRegistry[id].init != NULL) {
        gActorRegistry[id].init(actor);
    }
}

void update_actor() {
    for (int i = 0; i<gActorListSize; i++) {
        int id = gActorList[i].id;
        if (gActorRegistry[id].update != NULL) {
            gActorRegistry[id].update(&gActorList[i]);
        }
    }
}

void render_actor() {
    for (int i = 0; i<gActorListSize; i++) {
        int id = gActorList[i].id;
        if (gActorRegistry[id].render != NULL) {
            gActorRegistry[id].render(&gActorList[i]);
        }
    }
}

void custom_update() {
    printf("custom update");
}

void custom_render() {
    printf("custom render");
}

void init_mod() {
    int new_actor_id = register_actor((struct ActorRegistry) {});
    int new_actor_id2 = register_actor((struct ActorRegistry) {.render=custom_render, .update=custom_update});
}
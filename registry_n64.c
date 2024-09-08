#include <string.h>

typedef float Vec3f[3];

struct Actor {
    int id;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
};

struct ActorRegistry {
    void (*init)(struct Actor*);
    void (*render)(struct Actor*);
    void (*update)(struct Actor*);
};

void custom_update() {
    printf("custom update");
}

void custom_render() {
    printf("custom render");
}

struct ActorRegistry gActorRegistry[] = { {}, { .render = custom_render, .update = custom_update } };

enum { CUSTOM_ACTOR1, CUSTOM_ACTOR2 };

struct Actor gActorList[1024] = {};
int gActorListSize = 0;

void spawn_actor(int id, Vec3f position, Vec3f velocity, Vec3f rotation) {
    struct Actor* actor = &gActorList[gActorListSize];
    actor->id = id;
    memcpy(actor->position, position, sizeof(Vec3f));
    memcpy(actor->velocity, velocity, sizeof(Vec3f));
    memcpy(actor->rotation, rotation, sizeof(Vec3f));
    if (gActorRegistry[id].init != NULL) {
        gActorRegistry[id].init(actor);
    }
}

void update_actor() {
    for (int i = 0; i < gActorListSize; i++) {
        int id = gActorList[i].id;
        if (gActorRegistry[id].update != NULL) {
            gActorRegistry[id].update(&gActorList[i]);
        }
    }
}

void render_actor() {
    for (int i = 0; i < gActorListSize; i++) {
        int id = gActorList[i].id;
        if (gActorRegistry[id].render != NULL) {
            gActorRegistry[id].render(&gActorList[i]);
        }
    }
}

void init_mod() {
}

struct ActorSpawn {
    int id;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
};

struct ActorSpawn someActorSpawn[] = { { CUSTOM_ACTOR1, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 } },
                                       { CUSTOM_ACTOR2, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 } } };

void init_course() {
    for (int i = 0; i < 2; i++) {
        spawn_actor(someActorSpawn[i].id, someActorSpawn[i].position, someActorSpawn[i].velocity,
                    someActorSpawn[i].rotation);
    }
}
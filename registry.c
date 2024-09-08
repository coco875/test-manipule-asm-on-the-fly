#include <string.h>

typedef float Vec3f[3];

struct Actor {
    int id;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
    void (*render)(struct Actor*);
    void (*update)(struct Actor*);
};

typedef void (*ActorConstructor)(struct Actor*);

ActorConstructor gActorRegistry[1024] = {};
int gActorRegistrySize = 0;

int register_actor(void (*init)(struct Actor*)) {
    int id = gActorRegistrySize;
    gActorRegistry[id] = init;
    gActorRegistrySize++;
    return id;
}

struct Actor gActorList[1024] = {};
int gActorListSize = 0;

void spawn_actor(int id, Vec3f position, Vec3f velocity, Vec3f rotation) {
    struct Actor* actor = &gActorList[gActorListSize];
    actor->id = id;
    memcpy(actor->position, position, sizeof(Vec3f));
    memcpy(actor->velocity, velocity, sizeof(Vec3f));
    memcpy(actor->rotation, rotation, sizeof(Vec3f));
    if (gActorRegistry[id] != NULL) {
        gActorRegistry[id](actor);
    }
}

void update_actor() {
    for (int i = 0; i < gActorListSize; i++) {
        if (gActorList[i].update != NULL) {
            gActorList[i].update(&gActorList[i]);
        }
    }
}

void render_actor() {
    for (int i = 0; i < gActorListSize; i++) {
        if (gActorList[i].render != NULL) {
            gActorList[i].render(&gActorList[i]);
        }
    }
}

void custom_update(struct Actor* actor) {
    printf("custom update");
}

void custom_render(struct Actor* actor) {
    printf("custom render");
}

void custom_init(struct Actor* actor) {
    actor->update = custom_update;
    actor->render = custom_render;
}

int myActorID;
int myActorID2;

void init_mod() {
    myActorID = register_actor(NULL);
    myActorID2 = register_actor(custom_init);
}

struct ActorSpawn {
    int* id;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
};

struct ActorSpawn someActorSpawn[] = { { &myActorID, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 } },
                                       { &myActorID, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 }, { 0.0, 0.0, 0.0 } } };

void init_course() {
    for (int i = 0; i < 2; i++) {
        spawn_actor(&someActorSpawn[i].id, someActorSpawn[i].position, someActorSpawn[i].velocity,
                    someActorSpawn[i].rotation);
    }
}

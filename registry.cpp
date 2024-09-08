#include <string.h>
#include <vector>
#include <stdio.h>
#include <stdint.h>

typedef float Vec3f[3];

// class Actor; - If the compiler throws an error, uncomment this line;

class Actor {
  public:
    uint32_t id = 01;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
    Actor() {

    };

    virtual void init() {};
    virtual void render() {};
    virtual void update() {};

    // TODO: Move all this functions to a cpp file

    static uint32_t Size() {
        return gActorRegistry.size();
    }

    static void Clone(uint32_t id, Vec3f position, Vec3f velocity, Vec3f rotation) {
        Actor* actor = GetByID(id);

        if (actor == nullptr) {
            // TODO: Throw an error?
            return;
        }

        Actor cpy;
        memcpy((void*) &cpy, actor, sizeof(Actor));

        cpy.position = position;
        cpy.velocity = velocity;
        cpy.rotation = rotation;
    }
};

static std::vector<Actor*()> gActorRegistry;

static uint32_t register_actor(Actor* a()) {
    gActorRegistry.push_back(*a);
    return gActorRegistry.size() - 1;
}

static void update_actors() {
    for (size_t i = 0; i < Actor::Size(); i++) {
        gActorRegistry[i].update();
    }
}

static void render_actors() {
    for (size_t i = 0; i < Actor::Size(); i++) {
        gActorRegistry[i].render();
    }
}

void spawn_actor(int id, Vec3f position, Vec3f velocity, Vec3f rotation) {
    Actor* actor = &gActorList[gActorListSize];
    actor->id = id;
    memcpy(actor->position, position, sizeof(Vec3f));
    memcpy(actor->velocity, velocity, sizeof(Vec3f));
    memcpy(actor->rotation, rotation, sizeof(Vec3f));
    if (gActorRegistry[id] != NULL) {
        gActorRegistry[id](actor);
    }
}

class CustomActor : public Actor {};

class CustomActor2 : public Actor {
    void update() {
        printf("custom update 2");
    }

    void render() {
        printf("custom render 2");
    }
};

int myActorID;
int myActorID2;

void init_mod() {
    myActorID = register_actor([]() { return (Actor*) new CustomActor(); });
    myActorID2 = register_actor([]() { return (Actor*) new CustomActor2(); });
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
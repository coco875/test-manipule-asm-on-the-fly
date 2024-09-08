# Actor System
Actor are a main component of mk64 and should have idea on how it's structurate to be easy to manipulate for modder. Multiple thing are in constraint like be able to define a static list of actor to spawn.

## Actor ID
We will assume that all colision are determinate with is_collide and that gActorList contain all instance of actor and the size of gActorList are in gActorListSize. This can be change later and are not definitive. So the code are:
```c
void process_collision() {
    for (int i = 0; i<gActorListSize; i++) {
        for (int j = i+1; j<gActorListSize; j++) {
            if (is_collide(gActorList[i], gActorList[j])) {
                gActorList[i].collide(gActorList[j]);
                gActorList[j].collide(gActorList[i]);
            }
        }
    }
}
```
it's a simple way to check all pair of actor without check the same or two time the same pair (for example a and b, b and a). is_collide hide multiple type of collision from sphere to mesh collision. process_collision is the simple and naive way to do it, a more complex algorithm can be done later but a function to know how the object will react with are necessary.

* Actor should be able to know with what he collide with. So for this an id system can be necessary.
```C
void collision(Actor* actor) {
    if (actor->id==MUSHROOM) {
        actor->effect |= BOOST;
    } else {
        destroy(actor);
    }
}
```

* for update, render and other, id are not necessary, maybe some modded actor will need it.
* we should be able to add extra data to actor to handle more complex logic and properties.

## Actor Implementation

With all of that in mind we can use struct or class.
* Struct have the advantage to be "simple" and very close of the original code but it's more hard/less intuitive to add extra data. It give also the advantage to be be compatible with wasm who can be use to program with C, C++, js, python in an sandboxed environement.
* Class are more easy to manage for pur OOP. He are also compatible with lua but for other integration we will need to do C interface who can be complex or redundant with the C++ code.

example of registration system with struct:
```c
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
```

example of registration with C++

```C++
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
```

Multiple note:
* In example propose a fix for id where you reference a variable who have the id, id who get assigned later
* I split Actor registration and Actor object. It's another divergent point we will more info later.
* gActorRegistry and gActorList in C implementation can be a Vec.
* struct/class of actor have been simplified it's not only data/function they will have

## Actor Registration

As mentioned in a paragraph, we need id to help actor recognise other actor. We have two choice put an instance of the actor or make a special class/struct for that.
* With a Special Struct/class it make a clear difference between registraction and game. It can also mean not put init function in the struct to avoid redundancy. But mean split the constructor and the class.
* With an instance it's less extract code for each actor. But can confuse in the back-end and personally don't like but it's matter of taste.

Note: in the example above I applied the method split with combined in C++ it produce something like:

```C++
#include <string.h>
#include <vector>

typedef float Vec3f[3];

// class Actor; - If the compiler throws an error, uncomment this line;

class Actor {
  public:
    static std::vector<Actor*> gActorRegistry;
    uint32_t id = 01;
    Vec3f position;
    Vec3f velocity;
    Vec3f rotation;
    Actor();

    virtual void init() = 0;
    virtual void render() = 0;
    virtual void update() = 0;
    
    // TODO: Move all this functions to a cpp file

    static uint32_t Register(Actor* a){
        gActorRegistry.push_back(a);
        return gActorRegistry.size() - 1;
    }

    static uint32_t Size(){
        return gActorRegistry.size();
    }

    static Actor* GetByID(uint32_t id){
        if(gActorRegistry.size() > id){
            return;
        }
        return gActorRegistry[id];
    }
    
    static void Clone(uint32_t id, Vec3f position, Vec3f velocity, Vec3f rotation) {
        Actor* actor = GetByID(id);

        if(actor == nullptr){
            // TODO: Throw an error?
            return;
        }

        Actor cpy;
        memcpy((void*) &cpy, actor, sizeof(Actor));
        
        cpy.position = position;
        cpy.velocity = velocity;
        cpy.rotation = rotation;
    }

    static void Update(){
        for(size_t i = 0; i < Actor::Size(); i++){
            gActorRegistry[i].update();
        }
    }

    static void Render(){
        for(size_t i = 0; i < Actor::Size(); i++){
            gActorRegistry[i].render();
        }
    }
};

class CustomActor : public Actor {
    void update() {
        printf("custom update 1");
    }

    void render() {
        printf("custom render 1");
    }
};

class CustomActor2 : public Actor {
    void update() {
        printf("custom update 2");
    }

    void render() {
        printf("custom render 2");
    }
};

void init_mod() {
    uint32_t id = Actor::Register(new CustomActor());
    uint32_t id2 = Actor::Register(new CustomActor2());
}
```

## Actor on N64
The N64 have more limited performance and can't load code so the best will be to generate C code before compiling with all of that so very far of the dynamic registration like here.
The N64 will not use C++ or Vector because of their limited performance on memory with the ram bus, so dynamically allocate will cost more. And N64 possede not so much memory 4mb (or 8mb with expension pak) so reduce memory usage are better so smaller struct are better.

an implementation can be
```c
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
```

Multiple Note:
* gActorRegistry and the enum will be code generate at the compilation.
* Split each update, init, render function allow reduce the size of Actor of 12 bytes (4 bytes an ptr multiply by 3) so 12*1024=12ko so in modded enviroment on n64 it matter.

So multiple option are choose maybe there is other option. on pc we can put update and render in the struct we have more ram.

Personally I prefer a system with struct and split actor registration from actor but not have update and render in the struct don't matter so much for me.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../engine/quickjs.h"

#define JSRP_MAGIC "JSRP"
#define JSRP_VERSION 1

__attribute__ ((packed)) struct PackHeader {
    char magic[4];
    uint32_t version;
    uint32_t count;
};

struct PackResult {
    char* name;
    JSValue value;
};

static inline struct PackResult* js_unpack(JSContext* ctx, uint8_t* data, size_t length) {
    struct PackHeader* header = (struct PackHeader*)data;
    if(memcmp(header->magic, JSRP_MAGIC, 4)!= 0) {
        return NULL;
    }
    if(header->version!= JSRP_VERSION) {
        return NULL;
    }
    
    uint8_t* ptr = data + sizeof(struct PackHeader);
    uint8_t* ptr_end = data + length;
    struct PackResult* result = (struct PackResult*)malloc2(sizeof(struct PackResult) * header->count);
    memset(result, 0, sizeof(struct PackResult) * header->count);
    for(uint32_t i = 0; i < header->count; i++){
        size_t namesize = *(uint32_t*)ptr;
        ptr += 4;
        char* name = (char*)ptr;
        ptr += namesize;
        size_t size = *(uint32_t*)ptr;
        ptr += 4;

        if(ptr_end <= ptr || ptr + size > ptr_end){
            goto error;
        }

        result[i].name = strndup2(name, namesize);
        result[i].value = JS_ReadObject(ctx, ptr, size, JS_READ_OBJ_BYTECODE);
        ptr += size;
    }

    return result;

error:
    while (result -> name != NULL){
        free2(result->name);
        JS_FreeValue(ctx, result->value);
        result ++;
    }
    
    return NULL;
}
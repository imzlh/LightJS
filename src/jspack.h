#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../engine/quickjs.h"
#include "../engine/cutils.h"

#define JSRP_MAGIC "JSRP"
#define JSRP_MAGIC_ARR { 'J', 'S', 'R', 'P' }
#define JSRP_VERSION 1

#pragma once

__attribute__ ((packed)) struct PackHeader {
    char magic[4];
    uint32_t version;
    uint32_t count;
};

struct PackResult {
    char* name;
    JSValue value;
};

static inline struct PackResult* js_unpack(JSContext* ctx, uint8_t* data, size_t length, size_t* count) {
    struct PackHeader* header = (struct PackHeader*)data;
    if(memcmp(header->magic, JSRP_MAGIC, 4)!= 0) {
        return NULL;
    }
    if(header->version!= JSRP_VERSION) {
        return NULL;
    }
    
    uint8_t* ptr = data + sizeof(struct PackHeader);
    uint8_t* ptr_end = data + length;
    struct PackResult* result = (struct PackResult*)js_malloc(ctx, sizeof(struct PackResult) * header->count);
    memset(result, 0, sizeof(struct PackResult) * header->count);
    *count = header->count;
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

        result[i].name = strndup(name, namesize);
        result[i].value = JS_ReadObject(ctx, ptr, size, JS_READ_OBJ_BYTECODE);
        ptr += size;
    }

    return result;

error:
    while (result -> name != NULL){
        js_free(ctx, result->name);
        JS_FreeValue(ctx, result->value);
        result ++;
    }
    
    return NULL;
}

static inline uint8_t* js_pack(JSContext* ctx, struct PackResult* entries, uint32_t count, size_t* out_len) {
    DynBuf dbuf;
    size_t header_size = sizeof(struct PackHeader);
    
    dbuf_init(&dbuf);
    
    struct PackHeader header = {
        .magic = JSRP_MAGIC_ARR,
        .version = JSRP_VERSION,
        .count = count
    };
    dbuf_put(&dbuf, (uint8_t*)&header, header_size);

    for (uint32_t i = 0; i < count; i++) {
        size_t name_len = strlen(entries[i].name);
        dbuf_put_u32(&dbuf, name_len);
        dbuf_put(&dbuf, (uint8_t*)entries[i].name, name_len);
        
        size_t data_size;
        uint8_t* data = JS_WriteObject(ctx, &data_size, entries[i].value, JS_WRITE_OBJ_BYTECODE);
        if (!data) {
            dbuf_free(&dbuf);
            return NULL;
        }
        
        dbuf_put_u32(&dbuf, data_size);
        dbuf_put(&dbuf, data, data_size);
        js_free(ctx, data);
    }

    memcpy(dbuf.buf, &header, header_size);
    *out_len = dbuf.size;
    return dbuf.buf;
}

#define FIND_PACKAGE(_jspack, _count, _name, _value) \
    JSValue _value = JS_UNDEFINED; \
    for(uint32_t i = 0; i < _count; i++) { \
        if(strcmp((_jspack)[i].name, _name) == 0) { \
            _value = (_jspack)[i].value; \
            break; \
        } \
    }

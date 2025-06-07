
#include "utils.h"
#include "core.h"
#include "polyfill.h"
#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef LJS_LIBEXPAT
// parser
#include "expat.h"

struct XMLElement{
    JSValue name;
    JSValue attrs;
    struct Buffer content;

    JSValue obj;
    JSValue children;   // array
    int64_t child_count;
    struct list_head link;
};

struct JSXMLParserCtx {
    JSContext* ctx;

    XML_Parser parser;

    struct list_head stack;
};

#define FETCH(stack) list_entry((stack)->next, struct XMLElement, link)
#define POP(stack) list_del((stack) -> next);
#define PUSH(stack, el) list_add(&(el)->link, stack);

static struct JSXMLParserCtx* new_jsxmlctx(JSContext* ctx) {
    struct JSXMLParserCtx* jsxmlctx = js_malloc(ctx, sizeof(struct JSXMLParserCtx));
    jsxmlctx -> ctx = ctx;
    init_list_head(&jsxmlctx -> stack);
    return jsxmlctx;
}

static void free_jsxmlctx(struct JSXMLParserCtx* jsxmlctx) {
    XML_ParserFree(jsxmlctx -> parser);
    js_free(jsxmlctx -> ctx, jsxmlctx);
}

static void start_element(void* user_data, const XML_Char* name, const XML_Char** attrs) {
    struct JSXMLParserCtx* jsxmlctx = (struct JSXMLParserCtx*)user_data;

    if(name == NULL){   // xml meta
        name = "__meta__";
    }

    struct XMLElement* el = js_malloc(jsxmlctx -> ctx, sizeof(struct XMLElement));
    JSValue nameobj = JS_NewString(jsxmlctx -> ctx, name);
    el -> name = nameobj;
    el -> obj = JS_NewObject(jsxmlctx -> ctx);
    el -> children = JS_NewArray(jsxmlctx -> ctx);
    el -> child_count = 0;

    JSValue attrs_obj = JS_NewObject(jsxmlctx -> ctx);
    for (int i = 0; attrs[i]; i += 2) {
        char* name = (char*)attrs[i];
        JSValue value = JS_NewString(jsxmlctx -> ctx, attrs[i+1]);
        JS_SetPropertyStr(jsxmlctx -> ctx, attrs_obj, name, value);
    }
    el -> attrs = attrs_obj;

    memset(&el -> content, 0, sizeof(struct Buffer));
    PUSH(&jsxmlctx -> stack, el);
}

static void end_element(void* user_data, const XML_Char* name) {
    struct JSXMLParserCtx* jsxmlctx = (struct JSXMLParserCtx*)user_data;
    struct XMLElement* el = FETCH(&jsxmlctx -> stack);

    buffer_flat(&el -> content);
    char* content = (void*)el -> content.buffer;
    if(content) content[el -> content.end] = '\0';
    JSValue content_val = JS_NewStringLen(jsxmlctx -> ctx, content, el -> content.end);
    buffer_free(&el -> content);

    JSValue obj = el -> obj;
    JS_SetPropertyStr(jsxmlctx -> ctx, obj, "name", el -> name);
    JS_SetPropertyStr(jsxmlctx -> ctx, obj, "attributes", el -> attrs);
    JS_SetPropertyStr(jsxmlctx -> ctx, obj, "content", content_val);
    JS_SetPropertyStr(jsxmlctx -> ctx, obj, "children", el -> children);
    if(el -> child_count)
        JS_SetLength(jsxmlctx -> ctx, el -> children, el -> child_count);
    POP(&jsxmlctx -> stack);
    struct XMLElement* parent = FETCH(&jsxmlctx -> stack);
    JS_SetPropertyStr(jsxmlctx -> ctx, obj, "parent", JS_DupValue(jsxmlctx -> ctx, parent -> obj));
    JS_SetPropertyUint32(jsxmlctx -> ctx, parent -> children, parent -> child_count++, obj);

    js_free(jsxmlctx -> ctx, el);
}

static void char_data(void* user_data, const XML_Char* s, int len) {
    struct JSXMLParserCtx* jsxmlctx = (struct JSXMLParserCtx*)user_data;
    struct XMLElement* el = FETCH(&jsxmlctx -> stack);

    buffer_realloc(&el -> content, el -> content.size + len, true);
    buffer_push(&el -> content, (void*)s, len);
}

static inline XML_Parser xml_start(JSContext* ctx, struct JSXMLParserCtx* jsxmlctx){
    XML_Parser parser = jsxmlctx -> parser = XML_ParserCreate(NULL);
    XML_SetUserData(parser, jsxmlctx);
    XML_SetElementHandler(parser, start_element, end_element);
    XML_SetCharacterDataHandler(parser, char_data);

    JSValue root_obj = JS_NewObject(ctx);
    struct XMLElement* root = js_malloc(ctx, sizeof(struct XMLElement));
    memset(root, 0, sizeof(struct XMLElement));
    root -> name = JS_NewString(ctx, "<root>");
    root -> obj = root_obj;
    root -> children = JS_NewArray(ctx);
    JS_SetPropertyStr(ctx, root_obj, "name", root -> name);
    JS_SetPropertyStr(ctx, root_obj, "children", root -> children);
    PUSH(&jsxmlctx -> stack, root);
    return parser;
}

static inline void xml_end(XML_Parser parser, struct JSXMLParserCtx* jsxmlctx) {
    XML_ParseBuffer(parser, 0, true);
    struct XMLElement* root = FETCH(&jsxmlctx -> stack);
    JS_SetLength(jsxmlctx -> ctx, root -> children, root -> child_count);
    free_jsxmlctx(jsxmlctx);
}

static JSValue js_xml_parse(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) { 
    if (argc == 0) {
param_error:
        return LJS_Throw(ctx, "invaild arguments",
            "parse(xml: string): RootNode"
        );
    }

    const char* xmlstr = LJS_ToCString(ctx, argv[0], NULL);
    if (xmlstr == NULL) {
        goto param_error;
    }

    struct JSXMLParserCtx* jsxmlctx = new_jsxmlctx(ctx);
    XML_Parser parser = xml_start(ctx, jsxmlctx);

    int len = strlen(xmlstr);
    int i = 0;
    while (i < len) {
        int bytes_consumed = 0;
        void* buffer = XML_GetBuffer(parser, 1024);
        int bytes_to_read = MIN(len - i, 1024);
        memcpy(buffer, xmlstr + i, bytes_to_read);
        bytes_consumed = bytes_to_read;
        i += bytes_consumed;
        if (!XML_ParseBuffer(parser, bytes_consumed, false)) {
            goto error;
        }
    }

    JSValue root_obj = FETCH(&jsxmlctx -> stack)->obj;
    xml_end(parser, jsxmlctx);
    JS_FreeCString(ctx, xmlstr);
    return root_obj;

error:
    struct list_head* pos;
    list_for_each(pos, &jsxmlctx -> stack) {
        struct XMLElement* el = list_entry(pos, struct XMLElement, link);
        JS_FreeValue(ctx, el -> name);
        JS_FreeValue(ctx, el -> attrs);
        JS_FreeValue(ctx, el -> obj);
        JS_FreeValue(ctx, el -> children);
        buffer_free(&el -> content);
        js_free(ctx, el);
    }

    xml_end(parser, jsxmlctx);
    JS_FreeCString(ctx, xmlstr);
    const char* error_msg = XML_ErrorString(XML_GetErrorCode(parser));
    return JS_ThrowTypeError(ctx, "Failed to parse XML: %s", error_msg);
}

static const JSCFunctionListEntry js_xml_funcs[] = {
    JS_CFUNC_DEF("parse", 2, js_xml_parse),
};

#else

static const JSCFunctionListEntry js_xml_funcs[] = {
};

#endif

static int js_xml_init(JSContext* ctx, JSModuleDef* m) {
    return JS_SetModuleExportList(ctx, m, js_xml_funcs, countof(js_xml_funcs));
}

bool LJS_init_xml(JSContext* ctx) {
    JSModuleDef* m = JS_NewCModule(ctx, "xml", js_xml_init);
    if (!m) return false;
    JS_AddModuleExportList(ctx, m, js_xml_funcs, countof(js_xml_funcs));
    return true;
}

// TODO: xml from http stream interface
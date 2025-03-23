#include "../engine/quickjs.h"
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

static JSValue js_stdio_read(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    uint8_t *buf;
    size_t buf_len;
    bool to_str = false;

    if(argc == 0 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.readSync(filename: string, str?: boolean): string | Uint8Array");

    if(argc == 2)
        to_str = JS_ToBool(ctx, argv[1]);

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    FILE* fd = fopen(filename, "r");
    if (!fd) {
        LJS_Throw(ctx, "failed to open file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }
    if (fseek(fd, 0, SEEK_END) < 0) {
        fclose(fd);
        return LJS_Throw(ctx, "not a regular file", NULL);
    }
    long lret = ftell(fd);
    if (lret < 0 || fseek(fd, 0, SEEK_SET) < 0) {
        fclose(fd);
        return LJS_Throw(ctx, "not a regular file", NULL);
    }
    if(lret == LONG_MAX){
        fclose(fd);
        return LJS_Throw(ctx, "is a directory", NULL);
    }

    // 读取文件内容
    buf_len = lret;
    buf = malloc(buf_len + 1);
    if (!buf) {
        fclose(fd);
        return LJS_Throw(ctx, "out of memory", NULL);
    }
    if (fread(buf, 1, buf_len, fd) != buf_len) {
        free(buf);
        fclose(fd);
        return LJS_Throw(ctx, "failed to read file: %s", NULL, strerror(errno));
    }
    buf[buf_len] = '\0';
    fclose(fd);

    JSValue ret = to_str
        ? JS_NewStringLen(ctx, (char *)buf, buf_len)
        : JS_NewUint8Array(ctx, buf, buf_len, free_malloc, NULL, true);

    if(to_str) free(buf);
    return ret;
}

static JSValue js_stdio_stat(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    struct stat st;

    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.statSync(filename: string): object");

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    if (stat(filename, &st) < 0) {
        LJS_Throw(ctx, "failed to stat file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewBigInt64(ctx, st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewBigInt64(ctx, st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewBigInt64(ctx, st.st_ctime * 1000));
    JS_SetPropertyStr(ctx, obj, "ino", JS_NewInt64(ctx, st.st_ino));
    JS_SetPropertyStr(ctx, obj, "dev", JS_NewInt64(ctx, st.st_dev));
    JS_SetPropertyStr(ctx, obj, "mode", JS_NewInt32(ctx, st.st_mode));
    JS_SetPropertyStr(ctx, obj, "nlink", JS_NewInt64(ctx, st.st_nlink));
    JS_SetPropertyStr(ctx, obj, "uid", JS_NewInt64(ctx, st.st_uid));
    JS_SetPropertyStr(ctx, obj, "gid", JS_NewInt64(ctx, st.st_gid));

    if (S_ISDIR(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, true));
    } else if(S_ISREG(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, true));
        JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, st.st_size));
        
        JS_SetPropertyStr(ctx, obj, "blksize", JS_NewInt64(ctx, st.st_blksize));
        JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, st.st_blocks));
    } else if(S_ISCHR(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
        JS_SetPropertyStr(ctx, obj, "isCharacterDevice", JS_NewBool(ctx, true));
    } else if(S_ISBLK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
        JS_SetPropertyStr(ctx, obj, "isBlockDevice", JS_NewBool(ctx, true));
    } else if(S_ISFIFO(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isFIFO", JS_NewBool(ctx, true));
    } else if(S_ISSOCK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isSocket", JS_NewBool(ctx, true));
    } else if(S_ISLNK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, true));
        char* link_target = malloc(PATH_MAX + 1);
        if (readlink(filename, link_target, PATH_MAX) >= 0) {
            JS_SetPropertyStr(ctx, obj, "target", JS_NewString(ctx, link_target));
        }
        free(link_target);
    }
    return obj;
}

static JSValue js_stdio_write(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    uint8_t *data;
    size_t data_len;

    if(argc != 2 || !JS_IsString(argv[0]) || (!JS_IsString(argv[1]) && JS_TYPED_ARRAY_UINT8 != JS_GetTypedArrayType(argv[1])))
        return LJS_Throw(ctx, "invalid arguments", "stdio.write(filename: string, data: string | Uint8Array): void");

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    if(JS_IsString(argv[1])){
        data = (uint8_t*)JS_ToCStringLen(ctx, &data_len, argv[1]);
    }else{
        data = JS_GetUint8Array(ctx, &data_len, argv[1]);
    }
    if (!data)
        return JS_EXCEPTION;

    FILE* fd = fopen(filename, "w");
    if (!fd) {
        LJS_Throw(ctx, "failed to open file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }
    if (fwrite(data, 1, data_len, fd) != data_len) {
        fclose(fd);
        return LJS_Throw(ctx, "failed to write file: %s", NULL, strerror(errno));
    }
    fclose(fd);

    return JS_UNDEFINED;
}

// mkdir
static JSValue js_stdio_mkdir(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *path;
    size_t path_len;
    int mode = 0777;

    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.mkdir(path: string, mode: int): void");

    path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    if (mkdir(path, mode) < 0) {
        LJS_Throw(ctx, "failed to create directory: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

static bool get_all_files_or_dirs(const char* path, char*** list, uint32_t* list_length, uint32_t* list_used, bool stop_when_error){
    DIR* dir = opendir(path);
    bool error = false;

    if (!dir) {
        return false;
    }

    struct dirent* ent;
    while ((ent = readdir(dir))!= NULL) {
        if (ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue;
        }

        // is dir?
        if (ent->d_type == DT_DIR) {
            char* new_path = malloc(strlen(path) + strlen(ent->d_name) + 2);
            strcpy(new_path, path);
            strcat(new_path, "/");
            strcat(new_path, ent->d_name);
            if (!get_all_files_or_dirs(new_path, list, list_length, list_used, stop_when_error)){ 
                if (stop_when_error){
                    free(new_path);
                    closedir(dir);
                    return false;
                }else{
                    error = true;
                }
            }
            free(new_path);
        }else{
            if (*list_used >= *list_length) {
                *list_length += 16;
                *list = realloc(*list, *list_length * sizeof(char*));
            }
            (*list)[*list_used] = strdup(ent->d_name);
            (*list_used)++;
        }
    }
    closedir(dir);
    return error;
}

static inline JSValue dirent_type_to_str(JSContext *ctx, unsigned char d_type){
    switch (d_type) {
        case DT_REG:
            return JS_NewString(ctx, "file");
        case DT_DIR:
            return JS_NewString(ctx, "dir");
        case DT_LNK:
            return JS_NewString(ctx, "link");
        case DT_BLK:
            return JS_NewString(ctx, "blkdrv");
        case DT_CHR:
            return JS_NewString(ctx, "chardev");
        case DT_FIFO:
            return JS_NewString(ctx, "fifo");
        case DT_SOCK:
            return JS_NewString(ctx, "socket");
        default:
            return JS_NewString(ctx, "unknown");
    }
}

// unlink
static JSValue js_stdio_unlink(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.unlink(path: string): void");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    // stat is a dir or file
    struct stat st;
    if (stat(path, &st) < 0) {
        LJS_Throw(ctx, "failed to stat file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }
    if (S_ISDIR(st.st_mode)) {
        char** list = malloc(16 * sizeof(char*));
        uint32_t list_length = 16;
        uint32_t list_used = 0;
        if (!get_all_files_or_dirs(path, &list, &list_length, &list_used, true)) {
            LJS_Throw(ctx, "failed to get subfiles in this directory: %s", NULL, strerror(errno));
        }

        // delete all subfiles
        for (uint32_t i = 0; i < list_used; i++) {
            char* sub_path = malloc(strlen(path) + strlen(list[i]) + 2);
            strcpy(sub_path, path);
            strcat(sub_path, "/");
            strcat(sub_path, list[i]);
            if (unlink(sub_path) < 0) {
                LJS_Throw(ctx, "failed to remove file: %s", NULL, strerror(errno));
                return JS_EXCEPTION;
            }
            free(sub_path);
        }
        free(list);

        // delete dir
        if (rmdir(path) < 0) {
            LJS_Throw(ctx, "failed to remove directory: %s", NULL, strerror(errno));
            return JS_EXCEPTION;
        }

    } else {
        if (unlink(path) < 0) {
            LJS_Throw(ctx, "failed to remove file: %s", NULL, strerror(errno));
            return JS_EXCEPTION;
        }
    }

    return JS_UNDEFINED;
}

// symlink
static JSValue js_stdio_symlink(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.symlink(target: string, path: string): void");
    
    size_t target_len;
    const char *target = JS_ToCStringLen(ctx, &target_len, argv[0]);
    if (!target)
        return JS_EXCEPTION;

    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[1]);
    if (!path)
        return JS_EXCEPTION;

    if (symlink(target, path) < 0) {
        LJS_Throw(ctx, "failed to create symlink: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

// chmod
static JSValue js_stdio_chmod(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsNumber(argv[1])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.chmod(path: string, mode: int): void");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    uint32_t mode;
    if(!JS_ToUint32(ctx, &mode, argv[1]) || mode > 07777)
        return LJS_Throw(ctx, "invalid mode", NULL);

    if (chmod(path, mode) < 0) {
        LJS_Throw(ctx, "failed to change file mode: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

// realpath
static JSValue js_stdio_realpath(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.realpath(path: string): string");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    char* real_path = realpath(path, NULL);
    if (!real_path) {
        LJS_Throw(ctx, "failed to get real path: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    JSValue ret = JS_NewString(ctx, real_path);
    free(real_path);
    return ret;
}

// scandir
static JSValue js_stdio_scandir(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.scandir(path: string): array");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    DIR* dir = opendir(path);
    if (!dir) {
        LJS_Throw(ctx, "failed to open directory: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    struct dirent* ent;
    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue;
        }

        JSValue obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, ent->d_name));
        JS_SetPropertyStr(ctx, obj, "type", dirent_type_to_str(ctx, ent->d_type));
        JS_SetPropertyUint32(ctx, arr, i, obj);
        i++;
    }

    return arr;
}

// rename
static JSValue js_stdio_rename(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.rename(oldPath: string, newPath: string): void");
    
    size_t old_path_len;
    const char *old_path = JS_ToCStringLen(ctx, &old_path_len, argv[0]);
    if (!old_path)
        return JS_EXCEPTION;

    size_t new_path_len;
    const char *new_path = JS_ToCStringLen(ctx, &new_path_len, argv[1]);
    if (!new_path)
        return JS_EXCEPTION;

    if (rename(old_path, new_path) < 0) {
        LJS_Throw(ctx, "failed to rename file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

// open
static JSValue js_stdio_open(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc < 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, "invalid arguments", "stdio.open(path: string, flags: string, mode?: number): Pipe");
    
    size_t path_len;
    uint32_t mode = 0666;
    int flag = 0;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    const char *flags = JS_ToCString(ctx, argv[1]);
    
    if(argc == 3) JS_ToUint32(ctx, &mode, argv[2]);

    if (!path || !flags)
        return JS_EXCEPTION;

    // parse flags
    // flag1: r, w, a, x
    if(flags[0] != '\0'){
        if(flags[0] == 'r') flag |= O_RDONLY;
        else if(flags[0] == 'w') flag |= O_WRONLY | O_CREAT | O_TRUNC;
        else if(flags[0] == 'a') flag |= O_WRONLY | O_CREAT | O_APPEND;
        else if(flags[0] == 'x') flag |= O_WRONLY | O_CREAT | O_EXCL;
        else return LJS_Throw(ctx, "invalid flag", NULL);
    }
    // flag2/3: x, s, +
    if(flags[1] != '\0'){
        if(flags[1] == 'x') flag |= O_EXCL;
        else if(flags[1] == 's') flag |= O_SYNC;
        else if(flags[1] == '+') flag |= O_RDWR;
        else return LJS_Throw(ctx, "invalid flag", NULL);

        if(flags[2] != '\0' && flags[2] == '+'){
            flag |= O_RDWR;
        }
    }

    int fd = open(path, flag, mode);
    if (fd < 0) {
        LJS_Throw(ctx, "failed to open file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return LJS_NewFDPipe(ctx, fd, PIPE_READ | PIPE_WRITE, PIPE_BUF, JS_NULL);
}

static const JSCFunctionListEntry js_stdio_funcs[] = {
    JS_CFUNC_DEF("write", 2, js_stdio_write),
    JS_CFUNC_DEF("mkdir", 1, js_stdio_mkdir),
    JS_CFUNC_DEF("unlink", 1, js_stdio_unlink),
    JS_CFUNC_DEF("symlink", 2, js_stdio_symlink),
    JS_CFUNC_DEF("chmod", 2, js_stdio_chmod),
    JS_CFUNC_DEF("realpath", 1, js_stdio_realpath),
    JS_CFUNC_DEF("scandir", 1, js_stdio_scandir),
    JS_CFUNC_DEF("open", 2, js_stdio_open),
    JS_CFUNC_DEF("stat", 1, js_stdio_stat),
    JS_CFUNC_DEF("read", 2, js_stdio_read),
    JS_CFUNC_DEF("rename", 2, js_stdio_rename)
};

static int js_mod_stdio_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, js_stdio_funcs, countof(js_stdio_funcs));

    // stdin, stdout, stderr
    JSValue stdin_p = LJS_NewFDPipe(ctx, STDIN_FILENO, PIPE_READ, PIPE_BUF, JS_NULL),
        stdout_p = LJS_NewFDPipe(ctx, STDOUT_FILENO, PIPE_WRITE, PIPE_BUF, JS_NULL),
        stderr_p = LJS_NewFDPipe(ctx, STDERR_FILENO, PIPE_WRITE, PIPE_BUF, JS_NULL);

    JS_SetModuleExport(ctx, m, "stdin", stdin_p);
    JS_SetModuleExport(ctx, m, "stdout", stdout_p);
    JS_SetModuleExport(ctx, m, "stderr", stderr_p);

    return 0;
}

bool LJS_init_stdio(JSContext *ctx){
    JSModuleDef *m = JS_NewCModule(ctx, "stdio", js_mod_stdio_init);
    if (!m) return false;
    JS_AddModuleExportList(ctx, m, js_stdio_funcs, countof(js_stdio_funcs));
    JS_AddModuleExport(ctx, m, "stdin");
    JS_AddModuleExport(ctx, m, "stdout");
    JS_AddModuleExport(ctx, m, "stderr");

    return true;
}
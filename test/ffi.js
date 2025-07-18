import { dlopen, types } from "ffi"
import { exit, Process, self } from "process"
import { scandir, stat, unlink } from "fs"

console.warn("ffi is unstable and dangerous, use it with caution.")

self.cwd = import.meta.dirname;

// build
try{
    stat("libtest.so")
    unlink("libtest.so");
    throw 0;
}catch(e){
    console.debug(e);
    console.log("building libtest.so...")
    const proc = new Process(["gcc", "-shared", "-fPIC", "-O0", "-ggdb3", "libtest.c", "-o", "libtest.so"], {
        "inheritPipe": true
    });
    console.log('created process');
    await proc.onclose
    try{
        stat("libtest.so")
    }catch{
        console.error("failed to build libtest.so");
        console.log(scandir("."));
        exit(1);
    }
}

const handle = dlopen("libtest.so")

test("int+int", () => {
    const add = handle.bind([types.INT, "test_add", types.INT, types.INT]);
    assert(add(1, 2) == 3);
});

test("float+float", () => {
    assert(handle.apply([types.FLOAT, "test_addf", types.FLOAT, types.FLOAT], [1.5, 2.5]) == 4.0);
});

test("double+double", () => {
    assert(handle.apply([types.DOUBLE, "test_addd", types.DOUBLE, types.DOUBLE], [1.5, 2.5]) == 4.0);
});

test("malloc", () => {
    const func = handle.bind([types.POINTER, "test_malloc", types.INT]);
    const ptr = func(10).call(null, 10, false);
    console.log(decodeStr(new Uint8Array(ptr)));
})

// @ts-ignore
handle(null);   // free resources
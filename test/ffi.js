import { dlopen, types } from "ffi"
import { exit, Process, self } from "process"
import { scandir, stat, unlink } from "fs"

console.warn("ffi is unstable and dangerous, use it with caution.")

self.cwd = import.meta.dirname;

// build
try{
    stat("libtest.so")
}catch(e){
    console.log(e);
    console.log("building libtest.so...")
    const proc = new Process(["gcc", "-shared", "-fPIC", "-O0", "-ggdb3", "libtest.c", "-o", "libtest.so"], {
        "inheritPipe": true
    });
    console.log('created process');
    try{
        await proc.onclose
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
    const func = handle.bind([types.PTR('free'), "test_malloc", types.INT]);
    const ptr = func(12).call(null, 12, false);
    console.log(new Uint8Array(ptr));
})
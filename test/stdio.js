import { open, read, rename, scandir, stat, unlink, write } from "fs";

console.log('test stdio');

test("write sync", () => write("test.txt", "Hello World"));

test("read sync", () => read("test.txt", true) === "Hello World");
test("read binary sync", () => assert(isEqual(
    encodeStr("Hello World"),
    read("test.txt", false)
)))

test("rename", () => rename("test.txt", "test2.txt"));

test("stat", () => {
    const s = stat("test2.txt");
    assert(s.isFile);
    assert(s.size === "Hello World".length);
});

await test("open", async () => {
    const pipe = open("test2.txt", "r+");
    console.log(pipe);
    const res = await pipe.read("Hello World".length);
    if(!res) throw new Error("Read failed");
    console.log("read() result:", decodeStr(res));
    assert(isEqual(res, encodeStr("Hello World")), "Read mismatch with write");
    
    await pipe.write(encodeStr("Goodbye World"));
    await pipe.write(encodeStr("!!"));
    pipe.close();
    
    assert(pipe.closed, "Pipe should be closed after read");
});

test("unlink", () => unlink("test2.txt"));

test("scandir", () => console.log(scandir(".")));
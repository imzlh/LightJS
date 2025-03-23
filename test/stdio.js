import { open, read, rename, scandir, stat, unlink, write } from "stdio";

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

test("open", async () => {
    const pipe = open("test2.txt", "r+");
    assert(isEqual(pipe.read(), encodeStr("Hello World")));
    pipe.write(encodeStr("Goodbye World"));
    pipe.close();
});

test("unlink", () => unlink("test2.txt"));

test("scandir", () => console.log(scandir(".")));
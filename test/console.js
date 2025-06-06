import { exit, self, stderr, stdin, stdout } from "process";

// console test
test("console.log", () => console.log("Hello, world!"));
test("console.error", () => console.error("Error message"));
test("console.warn", () => console.warn("Warning message"));
test("console.debug", () => console.debug("Debug message"));
test("console.info", () => console.info("Info message"));
test("print objects", () => {
    console.log({a: 1, b: 2});
    console.log([1, 2, 3]);
    console.log(new Uint8Array(Array.from({length: 10}, (_, i) => Math.floor(Math.random() * 256))));

    const obj2 = {a: 1, b: 2};
    Object.defineProperty(obj2, Symbol("c"), {
        get: () => 4,
        set: (v) => {
            console.log("c is set to", v);
        }
    });
    console.log(obj2);

    const url = new URL("https://www.example.com/?a=1&b=2#hash");
    console.log(url);
})
test("console.count", () => {
    console.count();
    console.count();
    console.count();
    console.countReset();
    console.count();
});
test("console.time", () => {
    console.time("my-timer");

    // wait for 10 second
    delay(10000).then(() => console.timeEnd("my-timer"));
});
test("console.assert", () => console.assert(true, "Assertion passed"));
// test("console.clear", () => console.clear());


test('input', async () => {
    stdin.ttyRaw(true);
    await stdout.write(encodeStr("Enter 'hello' and press enter:"))
    const input = await stdin.readline();
    assert(isEqual(input, encodeStr("hello")), input ? decodeStr(input) : undefined);
    await stderr.write(encodeStr("\nPress any key to exit..."));
    console.log(await stdin.read());
    console.log("exit with code 0");
    exit(0);
})
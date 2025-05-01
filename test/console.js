// console test
test("console.log", () => console.log("Hello, world!"));
test("console.error", () => console.error("Error message"));
test("console.warn", () => console.warn("Warning message"));
test("console.debug", () => console.debug("Debug message"));
test("console.info", () => console.info("Info message"));
test("print objects", () => {
    console.log({a: 1, b: 2});
    console.log([1, 2, 3]);
    console.log(new Uint8Array([1, 2, 3]));
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
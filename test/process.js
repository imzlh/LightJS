import { stderr, stdin, stdout } from "process";

console.log("Starting process.js");

await test("std", async () => {
    stdout.write(encodeStr("Enter something and press enter: "));
    const data = await stdin.readline();
    stderr.write(encodeStr("You entered: " + data));
});

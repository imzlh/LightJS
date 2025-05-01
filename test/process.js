import { Process, stderr, stdin, stdout } from "process";

console.log("Starting process.js");

await test("std", async () => {
    stdout.write(encodeStr("Enter something and press enter: "));
    const data = await stdin.readline();
    if(data)
        stderr.write(encodeStr("You entered: " + decodeStr(data) + '\n'));
});

await test("subproc", async () => {
    const proc = new Process(['ls'], {
        inheritPipe: true
    });
    console.log(proc.alive, proc.pid);
    assert(proc.alive);
    assert(proc.pid > 0);
    await proc.onclose;
    assert(!proc.alive);
});

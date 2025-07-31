import { exit, Process, self, signals, stderr, stdin, stdout } from "process";

console.log("Starting process.js");

// await test("std", async () => {
//     stdin.ttyRaw(true);
//     stdout.write(encodeStr("Enter something and press enter: "));
//     const data = await stdin.readline();
//     if(data)
//         stderr.write(encodeStr("You entered: " + decodeStr(data) + '\n'));
//     await stdout.write(encodeStr("Press any key to continue..."));
//     await stdin.read(1);
// });

await test("subproc", async () => {
    const proc = new Process(['bash'], {
        inheritPipe: false
    });
    console.log(proc.alive, proc.pid);
    assert(proc.pipe);
    assert(proc.alive);
    assert(proc.pid > 0);
    await proc.pipe.write(encodeStr("echo 'Hello, world!'\n"));
    const res = await proc.pipe.read();
    assert(res);
    if(!res) return;    // for ts checking
    console.log(decodeStr(res));
    assert(decodeStr(res).includes("Hello, world!"))
    proc.pipe.write(encodeStr("exit\n"));
    await proc.onclose;
    assert(!proc.alive);
});

self.signal(signals.SIGTERM, () => {
    exit(0);
})
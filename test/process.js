import { exit, Process, self, signals, stderr, stdin, stdout } from "process";

console.log("Starting process.js");

await test("std", async () => {
    stdin.ttyRaw(true);
    stdout.write(encodeStr("Enter something and press enter: "));
    const data = await stdin.readline();
    if(data)
        stderr.write(encodeStr("You entered: " + decodeStr(data) + '\n'));
    await stdout.write(encodeStr("Press any key to continue..."));
    await stdin.read(1);
});

await test("subproc", async () => {
    const proc = new Process(['bash'], {
        inheritPipe: false
    });
    console.log(proc.alive, proc.pid);
    assert(proc.pipe);
    await proc.pipe.write(encodeStr("echo 'Hello, world!'\n"));
    assert(proc.alive);
    assert(proc.pid > 0);
    await proc.pipe.pipeTo(stdout);
    await proc.onclose;
    assert(!proc.alive);
});

self.signal(signals.SIGTERM, () => {
    exit(0);
})
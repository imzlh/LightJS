import { self, signals, stdout } from "process";
import { bind } from "socket";

const s = bind("tcp://0.0.0.0:888", async (client, addr) => {
    console.log("new client connected from", addr);
    while(!client.closed){
        // await stdout.write(encodeStr('| '));
        await client.readline().then(d => {
            if(!d) return;
            const str = decodeStr(d).replaceAll('\r', '\\r');
            return stdout.write(encodeStr(str));
        });
        // await stdout.write(encodeStr(' |\n'));
    }
}, {
    reuseaddr: false,
});
console.log("server started");
self.signal(signals.SIGINT, () => s());
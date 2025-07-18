import { stat, unlink } from "fs";
import { Handler } from "http"
import { self, signals } from "process";
import { bind } from "socket"

test('server', () => {
    try{
        stat("./test.sock");
        unlink("./test.sock");
    }catch{}

    const server = bind("unix:./test.sock", async (client, addr) => {
        const http = await Handler.from(client);
        while(true){
            console.log(http.request.path, http.request.headers);

            // http.status(200).send("Hello, World!").done();
            // http.status(200).chunked().done();

            let i = 0;
            // await new Promise(resolve => {
            //     const iv = setInterval(() => {
            //         http.send(`(${i ++})Hello, World! ${Date.now()}\n`);
            //         if(i == 10){ 
            //             clearTimer(iv);
            //             http.done().then(self => self.reuse()).then(() => resolve(null));
            //         }
            //         console.log(`(${i}) sent`);
            //     }, 1000);
            // });
            http.status(302).header('Content-Length', 'Hello, World!'.length.toString()).header("Location", "/test2").done();
            http.send('Hello, World!').done();
            await http.end;
            await http.reuse();
            http.chunked().done().send('Hello, World!').done();
        }
    });

    self.signal(signals.SIGTERM, () => server());
})
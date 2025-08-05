// // import { Handler } from "http";
// // import { self, signals, stdout } from "process";
// // import { bind } from "socket";

// // const s = bind("tcp://0.0.0.0:888", async (client, addr) => {
// //     console.log("new client connected from", addr);
// //     const ws = (await Handler.from(client)).ws();
// //     ws.onmessage = (data, is_fin) => {
// //         console.log("received message:", data.toString(), is_fin);
// //         ws.send("pong");
// //     };
// //     while(true){
// //         ws.send("hello");
// //         await delay(1000);
// //     }
// // }, {
// //     reuseaddr: false,
// // });
// // console.log("server started");
// // self.signal(signals.SIGINT, () => s());

// // test websocket
// import 'process';

// const ws = await fetch('ws://124.222.6.60:8800', {
//     websocket: true
// })
// // @ts-ignore
// ws.onmessage = (data, is_fin) => {
//     console.log("received message:", decodeStr(data), is_fin);
// }
// while(true){
//     await delay(1000 + Math.random() * 1000);
//     ws.send("hello");
// }
new URL('/')
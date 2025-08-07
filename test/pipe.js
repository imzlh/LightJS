import { open, read, write } from "fs";
import { connectAsync } from "../lib/io/socket";
import { connect } from "socket";

// await test('fdpipe', async () => {
//     write('a.txt', 'hello');
//     const pipe = open('a.txt', 'r');
//     const pipe2 = open('b.txt', 'w');
//     pipe.pipeTo(pipe2);
//     pipe.close();
//     pipe2.close();
//     assert(read('b.txt', true) == 'hello');
//     console.log("pipeTo passed")
// });

await test('pipe', async () => {
    const pipe = new U8Pipe({
        async pull(){
            return new Uint8Array([1, 2, 3]);
        },
        async write(data){
            console.log(data);
            throw new Error();   // close
        },
        close(){
            console.log('close');
        }
    });
    assert(pipe.closed == false);
    const readed = await pipe.read();
    console.log(readed);
    assert(isEqual(readed, new Uint8Array([1, 2, 3])));
    try{
        await pipe.write(new Uint8Array([4, 5, 6]));
    }catch(e){
        console.log('Pipe closed normally', e);
    }
    assert(pipe.closed == true);
})

/**
 * 
 * @param {number} max_write 
 * @returns 
 */
function createDebugPipe(max_write){
    let writed = 0;
    return new U8Pipe({
        async pull(){
            return new Uint8Array([1, 2, 3]);
        },
        async write(data){
            console.log(data);
            if(writed ++ > max_write)
                throw new Error();   // close
        },
        close(){
            console.log('closed');
        }
    });
}

await test('fdpipe', async () => {
    const conn = connect('tls://www.apple.com');
    conn.write(encodeStr("GET /library/test/success.html HTTP/1.1\r\nHost: www.apple.com\r\nConnection: close"));
    conn.write(encodeStr("\r\n\r\n"));
    await conn.sync();

    // 500 then close
    while(!conn.closed){
        console.log(await conn.read());
    }
});

await test('pipeto', async () => {
    // simpleServer(8000, async (pipe, addr) => {
    //     const line = await pipe.readline();
    //     console.log(line);
    //     pipe.write(encodeStr('hello'));
    //     await delay(3000);
    //     pipe.close();
    // });
    // await delay(1000);
    const pipe = await connectAsync("tls://www.apple.com");
    console.log("Connected");
    let sent = false;
    const pipe2 = new U8Pipe({
        async pull(){
            console.log("pull");
            if(sent){
                throw new Error();   // close
            }else{
                sent = true;
                return encodeStr("GET /library/test/success.html HTTP/1.1\r\nHost: www.apple.com\r\nConnection: close\r\n\r\n");
            }
        },
        write(data){
            console.log("write");
            console.log(decodeStr(data))
        },
        close(){
            console.log('close');
        }
    });
    await Promise.all([
        pipe.pipeTo(pipe2),
        pipe2.pipeTo(pipe)
    ]);
});
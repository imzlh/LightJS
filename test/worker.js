import { self } from "process";

self.cwd = import.meta.dirname;

if(Worker.isWorker){
    console.log("from worker");

    events.on("message", (msg) => {
        console.log(msg);
        Worker.postMessage("done");
    });

    Worker.postMessage("hello");

    await delay(1000);
    Worker.postMessage("done");
}else{
    console.log("Main thread");
    const worker = new Worker(import.meta.url);
    // @ts-ignore msg could be any that could be dup by QuickJS
    worker.onmessage = msg => {
        console.log(msg);
        if(msg === 'done'){ 
            worker.terminate();
        }
    }

    worker.postMessage('hello');
    worker.postMessage('world');
    worker.onclose = () => {
        console.log('worker closed');
    }
}
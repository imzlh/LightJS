import { self } from "process";

self.cwd = import.meta.dirname;

if(Worker.isWorker){
    console.info("from worker");

    events.on("message", (msg) => {
        console.log('from worker', msg);
        Worker.postMessage("done");
    });

    Worker.postMessage("hello");
}else{
    console.info("Main thread");
    const worker = new Worker(import.meta.url);
    // @ts-ignore msg could be any that could be dup by QuickJS
    worker.onmessage = msg => {
        console.info(msg);
        if(msg === 'done'){ 
            worker.terminate();
        }
    }

    worker.postMessage('hello');
    worker.postMessage('world');

    // setInterval(() => {
    //     worker.postMessage('done');
    // }, 2345);

    worker.onclose = () => {
        console.log('worker closed');
    }
}
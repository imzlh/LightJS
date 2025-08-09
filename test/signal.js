import { Process, self, signals } from "process";

// @ts-ignore in worker
if(Worker.onmessage){
    self.signal(signals.SIGIO, () => {
        console.log("SIGIO received(worker)");
    });
}else{
    // in main thread
    const worker = new Worker(self.entry, {
        module: true
    });
    self.signal(signals.SIGIO, () => {
        console.log("SIGIO received(mt)");
    });

    Process.kill(self.pid, signals.SIGIO);
    await delay(10000);
}
import { self, signals } from "process";
import { bind } from "socket";

/**
 * 
 * @param {number} port 
 * @param {(client: U8Pipe, addr: IAddr) => void} callback 
 */
export default async function simpleServer(port, callback) {
    const server_close = bind(`tcp://0.0.0.0:${port}`, callback);
    console.log(`Server listening on port ${port}`);
    self.signal(signals.SIGTERM, () => {
        console.log("SIGTERM received, closing server");
        server_close();
    });
}
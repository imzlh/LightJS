import { self, signals } from "process";
import { TelnetServer } from "./server";

const addr = self.argv[1] ?? "tcp://127.0.0.1:23";
const server = new TelnetServer(addr);

self.signal(signals.SIGTERM, () => server.close());
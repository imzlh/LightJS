import { self } from "process";
import serveFile from "../../lib/http/file";
import Server from "../../lib/http/server";
import { stat } from "fs";

const server = new Server("0.0.0.0:8000");

/**
 * 
 * @param {import("http").Handler} client 
 * @param {IAddr} addr 
 */
server.callback = async (client, addr) => {
    const url = new URL(client.request.path);
    url.path = url.path.replaceAll('//', '/')
        .replaceAll('..', '')
        .replaceAll('\\', '/')
        .replaceAll('/./', '/');
    try{
        if(stat(url.path).isDirectory){
            let rurl = url.toString() ;
            if(!rurl.endsWith('/')) rurl += '/';
            rurl += 'index.html';
            client.status(301).header("Location", rurl).done(true);
            return;
        }
    }catch{
        client.status(404).send("Not Found").done();
        return;
    }
    serveFile(client, (import.meta.dirname || self.dirname) + url.path);
};

server.run();
console.log("Server running at http://localhost:8000");

setInterval(() => {
    console.log(`Connections: ${server.connecions}`);
}, 10000);
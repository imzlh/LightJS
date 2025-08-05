import { self } from "process";
import serveFile from "../../lib/http/file";
import Server from "../../lib/http/server";
import { read, stat } from "fs";

const server = new Server("0.0.0.0:8000");
const indexPage = read(import.meta.dirname + "/index.html", true);
const baseDir = import.meta.dirname;

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

    if(url.path === '/'){
        client.status(200).send(indexPage).done();
        return;
    }else if(url.path == '/show_error'){
        throw new Error('Error');
    }

    if(client.request.method == 'POST'){
        const res = await client.request.formData();
        console.log(res);
        client.status(200).send(JSON.stringify(res)).done(true);
        return;
    }

    try{
        if(stat(baseDir + url.path).isDirectory){
            let rurl = url.toString() ;
            if(!rurl.endsWith('/')) rurl += '/';
            rurl += 'index.html';
            client.status(301).header("Location", rurl).done(true);
            return;
        }
    }catch(e){
        console.error('E', baseDir + url.path, e);
        client.status(404).send("Not Found").done();
        return;
    }
    serveFile(client, baseDir + url.path);
};

server.run();
console.log("Server running at http://localhost:8000");

setInterval(() => {
    console.log(`Connections: ${server.connecions}`);
}, 10000);
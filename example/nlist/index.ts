import { stat } from "fs";
import Server from "../../lib/http/server";
import serveFile from "../../lib/http/file";
import { renderToString } from '../../lib/tsrt/jsx-poly';
import Template from './template';
import { join } from "../../lib/io/path";

const $s = new Server('0.0.0.0:8080', true);
const wwwroot = '/';
// const $s = new Server('./a.sock', true);

$s.callback = (client, addr) => {
    const url = new URL(client.request.path);

    if(url.path.startsWith('/@static/')){
        const path = import.meta.dirname + url.path.slice(8);
        return serveFile(client, path);
    }

    try{
        var stats = stat(join(wwwroot, url.path));
    }catch(e){
        client.send("File or Directory not found")
            .status(404)
            .done();
        return;
    }

    if(stats.isFile){
        serveFile(client, url.path);
    }else if(stats.isDirectory){
        const res = renderToString(Template({
            wwwroot,
            dir: url.path,
        }));
        client.send(res).header('Content-Type', 'text/html').done(true);
    }
}
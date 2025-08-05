import { open, stat } from "fs";
import { Handler } from "http";

// 检测aio
// let aio_cap = true;
// try{
//     open("/dev/random", 'r').close();
// }catch{
//     aio_cap = false;
// }

/**
 * 
 * @param {Handler} handler 
 * @param {string} file 
 */
export default function serveFile(handler, file) {
    try{
        var fh = open(file, 'r', undefined, true);
    }catch(e){
        console.error(file, e);
        handler.status(404).send("Not Found").done();
        return;
    }

    const ext = file.split('.').pop(),
        type = Handler.mimetype(ext || 'html'),
        fs = stat(file);
    if(!fs.isFile || !fs.size) return handler.status(403).send("Forbidden").done();
    
    handler.header('Content-Type', type);
    handler.header('Content-Length', fs.size.toString());

    const im = handler.headers.get('if-modified-since');
    if(im && new Date(im).getTime() < fs.mtime){
        handler.status(304).done(true);
        return;
    }

    // range?
    const range = handler.headers.get('range');
    let size = fs.size;
    if(range){
        const parts = range.match(/bytes=(\d+)-(\d+)?/);
        if(parts){
            const start = parseInt(parts[1]);
            const end = parts[2]? parseInt(parts[2]) : fs.size - 1;
            size = end - start + 1;
            handler.header('Content-Range', `bytes ${start}-${end}/${fs.size}`);
            handler.header('Content-Length', size.toString());
            handler.status(206);
            try{
                fh.seek(start, 0);
            }catch{
                return handler.status(416).done(true);
            }
        }else{
            return handler.status(416).done(true);
        }
    }else{
        handler.status(200);
    }

    handler.done();

    while(!fh.eof){
        // 128k speed
        const chunk = fh.read(128 * 1024);
        handler.send(chunk);
    }

    handler.done();
}
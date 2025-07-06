import { self } from "process";
import { basename, dirname } from "./io/path";
import { read, scandir, write } from "fs";
import Path from "./io/pypath";
import { Module, pack, Sandbox } from "vm";

const dir = dirname(self.entry);
self.cwd = dir;

/**
 * @type {Record<string, Module>}
 */
const obj = {};
/**
 * @type {Array<string>}
 */
const stack = [];
/**
 * @type {Sandbox}
 */
const sandbox = new Sandbox({
    loader: (input) => {
        if(input in obj) throw new Error('Module already loaded');
        const file = read(input, true);
        const mod = sandbox.loadModule(file, input);
        obj[input] = mod;
        console.log('| '.repeat(stack.length *2), '└─', stack.at(-1), mod.dump().byteLength);
        return mod;
    }
});
/**
 * @param {Path} path 
 */
function recursive(path) {
    for(const entry of scandir(path.toString())){
        const objPath = path.join(entry.name);
        if(entry.type == 'file' && entry.name.endsWith('.js')) try{
            sandbox.loadModule(read(objPath.toString(), true), objPath.relative);
        }catch(e){
            console.error('Failed to compile file', objPath.toString(), e);
        }else if(entry.type == 'directory'){
            recursive(objPath);
        }
    }
}

recursive(new Path('.'));

const res = pack(obj);
write(basename(self.entry) + '.jspack', res);
console.log('Bundle created successfully');
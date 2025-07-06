/**
 * 仿Python的path模块
 */

import { open, realpath, scandir } from "fs";

export default class Path {
    /**
     * @type {string}
     */
    #path;

    /**
     * @type {string}
     */
    #relative;

    /**
     * 
     * @param {string | Path} path 
     * @param {string | Path} relative 
     */
    constructor(path, relative = path) {
        if (path instanceof Path) {
            this.#path = path.#path;
            this.#relative = relative.toString() ?? path.#relative;
        } else {
            if( path[path.length - 1] == '/' ) path = path.slice(0, -1);
            if( typeof relative =='string' && relative[relative.length - 1] == '/' )
                relative = relative.slice(0, -1);
            if (!path.startsWith("/") && !path.match(/^[a-zA-Z]:/)) {
                this.#path = realpath(path);
            } else {
                this.#path = path;
            }
            this.#relative = relative.toString() ?? path;
        }
    }

    get parent() {
        let arr = this.#path.split("/");
        arr.pop();
        return new Path(arr.join("/"));
    }

    get name() {
        let arr = this.#path.split("/");
        return arr[arr.length - 1];
    }

    get stem() {
        let arr = this.#path.split("/");
        let name = arr[arr.length - 1];
        let index = name.lastIndexOf(".");
        if (index === -1) {
            return name;
        } else {
            return name.slice(0, index);
        }
    }

    get suffix() {
        let arr = this.#path.split("/");
        let name = arr[arr.length - 1];
        let index = name.lastIndexOf(".");
        if (index === -1) {
            return "";
        } else {
            return name.slice(index + 1);
        }
    }

    get relative() {
        return this.#relative;
    }

    /**
     * 
     * @param {string} suffix 
     * @returns 
     */
    with_suffix(suffix) {
        let arr = this.#path.split("/");
        let name = arr[arr.length - 1];
        let index = name.lastIndexOf(".");
        let index2 = this.#relative.length - (name.length - index);
        if (index === -1) {
            return new Path(this.#path + "." + suffix, this.#relative + "." + suffix);
        } else {
            return new Path(
                this.#path.slice(0, index) + "." + suffix,
                this.#relative.slice(0, index2) + "." + suffix
            );
        }
    }

    *iterdir() {
        const files = scandir(this.#path);
        yield* files.map(file => new Path(this.#path + "/" + file.name, this.#relative + "/" + file.name));
    }

    /**
     * 
     * @param {string | Path} path 
     * @returns 
     */
    join(path) {
        if (path instanceof Path) {
            path = path.toString();
        }
        if (path.startsWith("/")) {
            return new Path(this.#path + path, this.#relative + path.slice(1));
        } else {
            return new Path(this.#path + "/" + path, this.#relative + "/" + path);
        }
    }

    toString() {
        return this.#path;
    }
}

if(import.meta.main){
    let p = new Path("/root/lightjs/lib/io/pypath.js");
    console.log(p, p.join("test.txt"));

    p = new Path(".");
    console.log(p, p.join("pypath.js"));
}
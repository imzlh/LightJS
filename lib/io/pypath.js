/**
 * 仿Python的path模块
 */

import { realpath, scandir } from "fs";

export default class Path{
    /**
     * @type {string}
     */
    #path;

    /**
     * 
     * @param {string | Path} path 
     */
    constructor(path){
        if(path instanceof Path){
            this.#path = path.toString();
        }else{
            this.#path = realpath(path);
        }
    }

    get parent(){
        let arr = this.#path.split("/");
        arr.pop();
        return new Path(arr.join("/"));
    }

    get name(){
        let arr = this.#path.split("/");
        return arr[arr.length-1];
    }

    get stem(){
        let arr = this.#path.split("/");
        let name = arr[arr.length-1];
        let index = name.lastIndexOf(".");
        if(index === -1){
            return name;
        }else{
            return name.slice(0, index);
        }
    }

    get suffix(){
        let arr = this.#path.split("/");
        let name = arr[arr.length-1];
        let index = name.lastIndexOf(".");
        if(index === -1){
            return "";
        }else{
            return name.slice(index+1);
        }
    }

    /**
     * 
     * @param {string} suffix 
     * @returns 
     */
    with_suffix(suffix){
        let arr = this.#path.split("/");
        let name = arr[arr.length-1];
        let index = name.lastIndexOf(".");
        if(index === -1){
            return new Path(this.#path + "." + suffix);
        }else{
            return new Path(this.#path.slice(0, index) + "." + suffix);
        }
    }

    *iterdir(){
        const files = scandir(this.#path);
        yield* files.map(file => new Path(this.#path + "/" + file.name));
    }

    /**
     * 
     * @param {string | Path} path 
     * @returns 
     */
    join(path){
        if(path instanceof Path){
            path = path.toString();
        }
        if(this.#path.endsWith("/")){
            if(path.startsWith("/")){
                return new Path(this.#path + path.slice(1));
            }else{
                return new Path(this.#path + path);
            }
        }else{
            if(path.startsWith("/")){
                return new Path(this.#path + path);
            }else{
                return new Path(this.#path + "/" + path);
            }
        }
    }

    toString(){
        return this.#path;
    }
}
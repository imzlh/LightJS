import { scandir } from "fs";
import { join } from "./path";

/**
 * 
 * @param {string} pathBase 
 * @param {number} level
 * @param {Array<{name: string, path: string}>} targetObj
 */
function __tree(pathBase, level, targetObj = []){
    for(const dirent of scandir(pathBase)){
        if(dirent.type == 'dir'){
            const newPath = join(pathBase, dirent.name);
            __tree(newPath, level + 1, targetObj);
        }else{
            targetObj.push({
                name: dirent.name,
                path: join(pathBase, dirent.name)
            });
        }
    }
}
/**
 * 
 * @param {string} pathBase 
 * @returns 
 */
export function tree(pathBase){
    const files = /** @type {{name: string, path: string}[]} */ ([]);
    __tree(pathBase, 0, files);
    return files;
}
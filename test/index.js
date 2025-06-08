/**
 * LightJS Unit test V1
 */

import { self } from "process";
import { scandir } from "fs";
// import { read } from "fs";

/**
 * 
 * @param {string} name 
 * @param {() => any} assert_func 
 */
globalThis.test = async function(name, assert_func){
    let success = true;
    /** @type {Error} */ let error = new Error('success');
    try{
        await assert_func();
    }catch(e){
        error = e instanceof Error ? e : new Error(String(e));
        success = false;
    }
    (success ? console.log : console.error)('Try', name, 
        success ? 'succeed' : ('error:' + error.name + '\n' + ' '.repeat(4) + error.message + '\n' + error.stack)
    )
    success || console.error(error);
}

/**
 * 
 * @param {string} name 
 * @param {() => any} assert_func 
 */
globalThis.test2 = async function(name, assert_func){
    let success = false;
    /** @type {Error} */ let error = new Error('success');
    try{
        await assert_func();
    }catch(e){
        success = true;
        error = e instanceof Error ? e : new Error(String(e));
    }
    (success ? console.log : console.error)('Try', name, 'Failed: success');
    if(success) console.error(error);
}

/**
 * 
 * @param {any} expression
 * @param {string} message 
 */
globalThis.assert = function(expression, message = 'Assertion failed'){
    if(!expression) throw new Error(message);
}

/**
 * 
 * @param {any} value 
 * @param {any} other 
 * @returns 
 */
globalThis.isEqual = function(value, other) {
    // 类型检查
    if (value === other) return true;
    if (value == null || other == null) return false;
    if (typeof value !== 'object' || typeof other !== 'object') return false;

    // 对象类型检查
    const valueIsArray = Array.isArray(value);
    const otherIsArray = Array.isArray(other);

    if (valueIsArray !== otherIsArray) return false;

    // 对象或数组长度检查
    const valueKeys = Object.keys(value);
    const otherKeys = Object.keys(other);

    if (valueKeys.length !== otherKeys.length) return false;

    // 递归比较对象的每个属性
    for (let key of valueKeys) {
        if (!otherKeys.includes(key) || !isEqual(value[key], other[key])) {
            return false;
        }
    }

    return true;
}

if(import.meta.main && !Worker.onmessage){
    const file = self.argv[0];
    if(!file){
        console.log(self, import.meta);
        throw new Error('Expect an arg to run test');
    }
    /** @type {string[]} */ let paths;

    if(file == 'all'){
        paths = scandir(import.meta.dirname)
            .filter(item => item.type == 'file' && item.name.endsWith('.js') && (!item.name.startsWith('_') && !item.name.startsWith('index.js')))
            .map(item => item.name.slice(0, -3));
    }else{
        paths = [import.meta.dirname + '/' + file + '.js'];
    }

    for(const path of paths) try{
        console.log('Running test:', path);
        await import(path)
    }catch(e){
        console.error('Could not load test:' + file, e)
    }
}
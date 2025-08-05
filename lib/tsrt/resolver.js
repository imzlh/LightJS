import { read, realpath, stat } from "fs";
import { compile, loadSourceMap, Module, setVMOptions } from "vm";
import { transform } from "./tsutils";
import { dirname, join } from "../io/path";

const tfs = ["typescript", "jest"];

/**
 * @param {import("./tsutils").Transform} name 
 */
export function addTransformer(name){
    tfs.push(name);
}

const vMap = /** @type {Map<string, string>} */ (new Map());
/**
 * @param {string} name 
 * @param {string} code 
 */
export function addVModule(name, code) {
    vMap.set(name, code);
}

/**
 * 解析 import 路径
 * @param importPath {string} 要解析的路径 (可以是相对路径或绝对路径)
 * @param baseDir {string} 基础目录 (用于解析相对路径，默认为当前工作目录)
 * @returns 返回解析后的绝对路径
 */
export default function resolveImportPath(importPath, baseDir) {
    let normalizedPath = importPath;

    // 处理绝对路径
    if (importPath.startsWith('/')) {
        normalizedPath = importPath;
    }else{
        baseDir = dirname(baseDir);
        normalizedPath = join(baseDir, importPath).replaceAll(/\/[^/]*\/\.\.\//g, '/');
    }
    
    try {
        const pathStat = stat(normalizedPath);
        
        // 如果是符号链接，获取真实路径
        if (pathStat.isSymbolicLink) {
            return realpath(normalizedPath);
        }
        
        // 如果是目录，检查是否有 index 文件
        if (pathStat.isDirectory) {
            const indexPath = `${normalizedPath}/index`;
            return resolveImportPath(indexPath, '');
        }
        
        // 普通文件直接返回
        return realpath(normalizedPath);
    } catch (err) {
        // 尝试添加扩展名
        const extensions = ['.js', '.ts', '.json', '.jsx', '.tsx'];
        for (const ext of extensions) {
            try {
                const pathWithExt = `${normalizedPath}${ext}`;
                const statResult = stat(pathWithExt);
                if (statResult.isFile) {
                    return realpath(pathWithExt);
                }
            } catch {
                // 继续尝试下一个扩展名
            }
        }
        
        throw new Error(`Cannot resolve import path: ${importPath} with base dir: ${baseDir}`);
    }
}

setVMOptions({
    moduleResolver: (module_name, base_name) => {
        if((module_name.includes('/') || module_name.startsWith('.')) && !vMap.has(module_name))
            return resolveImportPath(module_name, base_name);
        else         // internal C module
            return module_name;
    },
    moduleLoader: (module_name) => {
        let content;
        if(vMap.has(module_name)){
            content = /** @type {string} */ (vMap.get(module_name));
        }else{
            content = read(module_name, true);
        }
        if(module_name.endsWith('.js') || module_name.endsWith('.json'))
            return content;
        const { code, sourceMap } = transform(content, {
            filePath: module_name,
            preserveDynamicImport: true,
            disableESTransforms: true,
            jsxRuntime: "automatic",
            production: true,
            jsxPragma: "createElement",
            jsxFragmentPragma: "Fragment",
            jsxImportSource: realpath(import.meta.dirname),
            injectCreateRequireForImportRequire: true,
            enableLegacyTypeScriptModuleInterop: false,
            transforms: /** @type {any} */ (tfs),
            sourceMapOptions: {
                compiledFilename: module_name
            }
        });
        loadSourceMap(module_name, /** @type {Object} */ (sourceMap));
        return code;
    }
})

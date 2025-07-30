/**
 * 非常简单的HTTP客户端
 */

import { connectAsync } from "../../lib/io/socket";

export class H1Client {
    /**
     * 
     * @param {U8Pipe} pipe 
     */
    static async readHeader(pipe){
        const h = /** @type {Record<string, string>} */ ({});
        while(true){
            const line = await pipe.readline();
            if(!line) break;
            const lineContent = decodeStr(line);
            const st = lineContent.indexOf(':');
            if(st === -1) continue;
            const key = lineContent.slice(0, st).trim();
            const value = lineContent.slice(st+1).trim();
            h[key] = value;
        }
        return h;
    }

    /**
     * 
     * @param {U8Pipe} pipe 
     * @returns 
     */
    static async readFirstLine(pipe){
        const line = await pipe.readline();
        if(!line) return null;
        const res = decodeStr(line).match(/^HTTP\/1.\d (\d{3}) (.*)$/);
        if(!res) throw new Error("Invalid response");

        return {
            status: parseInt(res[1]),
            statusText: res[2]
        };
    }

    static async request(url, method, headers, body){
        const conn = connectAsync(``)
    }


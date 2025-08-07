/**
 * 提供LJS自带的C fetch的封装
 */

import { Response } from "http";
import { resolveDNS } from "socket";

/**
 * @typedef {Object} FetchAdditionOptions
 * @property {(response: Response) => boolean | undefined} [onRedirect]
 * @property {'follow' | 'error' | 'ignore'} [redirect]
 */

/**
 * 更接近浏览器的fetch
 *  - 异步DNS解析
 *  - 自动处理重定向
 * 
 * @param {URL | string} url 
 * @param {FetchOptions<undefined> & FetchAdditionOptions} options 
 */
export default async function fetch(url, options) {

    // domain?
    if(String(url).match(/[a-z]+\.[a-z]{2,10}/)){
        // 异步解析DNS
        const url2 = url instanceof URL? url : new URL(url);
        const [v4, v6] = await Promise.all([
            resolveDNS(url2.host, "::"),
            resolveDNS(url2.host, "0.0.0.0")
        ]);
        const v6addr = /** @type {DNS_NORM[]} */ (v6.filter(i => i.type == 'AAAA' && i.data)),
            v4addr = /** @type {DNS_NORM[]} */ (v4.filter(i => i.type == 'A' && i.data));
        if(v6addr.length > 0){
            url2.host = v6addr[0].data;
            url = url2.toString();
        }else if(v4addr.length > 0){
            url2.host = v4addr[0].data;
            url = url2.toString();
        }else{
            throw new Error(`DNS resolve for ${url2.host} failed`);
        }
    }

    const fe = await globalThis.fetch(String(url), options);

    // 处理重定向
    if(fe.status >= 300 && fe.status < 400 && fe.headers.has('location')){
        if (options.redirect === 'follow') {
            const location = fe.headers.get('Location');
            if (location && (!options.onRedirect || options.onRedirect(fe))) {
                const redirectUrl = new URL(location, String(url));
                return fetch(redirectUrl, options);
            }
        }else if(options.redirect === 'error'){
            throw new Error(`Fetch redirect to ${fe.headers.get('Location')} but redirect option is error`);
        }
    }

    return fe;
}

/**
 * 提供LJS自带的C fetch的封装
 */

import { Response } from "http";

/**
 * @typedef {Object} FetchAdditionOptions
 * @property {(response: Response) => boolean | undefined} [onRedirect]
 * @property {'follow' | 'error' | 'ignore'} [redirect]
 */

/**
 * 增加重定向功能的fetch，更接近浏览器的fetch
 * @param {URL | string} url 
 * @param {FetchOptions<undefined> & FetchAdditionOptions} options 
 */
export default async function fetch(url, options) {
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

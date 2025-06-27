import { connect } from "socket";

/**
 * Open a socket connection to a remote host asynchronously.
 * @param {Parameters<typeof connect>} data 
 * @returns {Promise<U8Pipe>}
 */
export function connectAsync(...data){
    const pipe = connect.apply(null, data);
    return new Promise((resolve, reject) => {
        pipe.onclose.catch(reject);
        pipe.sync().then(() => resolve(pipe));
    });
}
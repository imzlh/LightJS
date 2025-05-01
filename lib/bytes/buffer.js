/**
 * Merge multiple buffers into one buffer.
 * @template T
 * @param {(T extends TypedArray? T : TypedArray)[]} buffers
 * @returns {T}
 */
export function mergeBuffers(...buffers) {
    const total = buffers.reduce((sum, arr) => sum + arr.length, 0);
    // @ts-ignore Call constructor
    const result = new (buffers[0].constructor)(total);
    let offset = 0;

    for (const arr of buffers) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
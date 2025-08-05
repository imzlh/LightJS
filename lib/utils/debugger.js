/**
 * debugger polyfill for QuickJS
 */

Object.defineProperty(globalThis, 'debugger', {
    enumerable: false,
    configurable: true,
    get: function() {
        const stack = new Error('debugger statement').stack;
        console.log('DEBUGGER statement \n', stack);
        return undefined;
    }
})
// Please note this numbers is not real.
// It is only used for type checking.
type _AUTO = 0;
type _VOID = 1;
type _INT = 2;
type _FLOAT = 3;
type _DOUBLE = 4;
type _LONGDOUBLE = 5;
type _UINT8 = 6;
type _SINT8 = 7;
type _UINT16 = 8;
type _SINT16 = 9;
type _UINT32 = 10;
type _SINT32 = 11;
type _UINT64 = 12;
type _SINT64 = 13;
type _POINTER = 14;
type _R_PTR = 15;

interface CTypes {
    AUTO: _AUTO;
    VOID: _VOID;
    INT: _INT;
    FLOAT: _FLOAT;
    DOUBLE: _DOUBLE;
    LONGDOUBLE: _LONGDOUBLE;
    UINT8: _UINT8;
    SINT8: _SINT8;
    UINT16: _UINT16;
    SINT16: _SINT16;
    UINT32: _UINT32;
    SINT32: _SINT32;
    UINT64: _UINT64;
    SINT64: _SINT64;
    POINTER: _R_PTR;
    R_PTR: (flag?: "free" | "jsfree" | undefined) => _R_PTR;
}

type CTypesVal = _AUTO | _VOID | _INT | _FLOAT | _DOUBLE | _LONGDOUBLE | _UINT8 | _SINT8 | _UINT16 | _SINT16 | _UINT32 | _SINT32 | _UINT64 | _SINT64 | _POINTER | _R_PTR;

type InferFrom<T extends CTypesVal> = 
    T extends _AUTO ? any :
    T extends _VOID ? void :
    T extends _INT ? number :
    T extends _FLOAT ? number :
    T extends _DOUBLE ? number :
    T extends _LONGDOUBLE ? number :
    T extends _UINT8 ? number :
    T extends _SINT8 ? number :
    T extends _UINT16 ? number :
    T extends _SINT16 ? number :
    T extends _UINT32 ? number :
    T extends _SINT32 ? number :
    T extends _UINT64 ? bigint :
    T extends _SINT64 ? number :
    T extends _POINTER ? number :
    T extends _R_PTR ? (length: number, shared?: boolean) => ArrayBuffer :
    never;

type InferTuple<T extends any[]> = {
    [K in keyof T]: InferFrom<T[K]>;
};

type Handler = <R extends CTypesVal, P extends (CTypesVal)[], T extends [R, string, ...P]>(this: T, ...args: InferTuple<P>) => InferFrom<R>;

declare module 'ffi' {
    export interface DLHandler extends Handler {
        bind<R extends CTypesVal, P extends CTypesVal[]>(
            thisArg: [R, string, ...P]
        ): (...args: InferTuple<P>) => InferFrom<R>;
    }
    
    export function dlopen(path: string): DLHandler;
    export const types: CTypes;
}


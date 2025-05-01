/**
 * LightJS HTTP module
 * source: src/http.c
 */

interface FormData {
    name: string;
    filename?: string;
    type?: string;

    data: Uint8Array;
}

declare module 'http' {
    export class Response {
        text(): Promise<string>;
        bytes(): Promise<Uint8Array>;
        json(): Promise<any>;
        formData(): Promise<FormData[]>;

        get locked(): boolean;
        get headers(): Record<string, string>;
        get body(): U8Pipe;
        get status(): number;
        get ok(): boolean;
    }
}
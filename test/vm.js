import { Sandbox } from "vm";

test('sandbox', async () => {
    const evals = /** @type {Array<[string, any]>} */ ([
        ['1 + 1', 2],
        ['console.log("hello")', undefined],
        ['new Function("return 1 + 1")()', 2],
        ['import.meta.main', true]
    ]);

    const sb = new Sandbox({
        loader(mod){
            console.log('importing', mod);
            throw new Error('not implemented');
        }
    })
    for (const [code, result] of evals) try{
        const res = await sb.eval(code, { main: true });
        console.log(code, '=>', res);
        assert(isEqual(res, result));
    }catch(e){
        console.error(code, 'failed: ', e);
    }
})
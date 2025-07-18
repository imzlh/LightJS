import { deflate, zlib } from "compress";

test('compress', function() {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    const ob = zlib(buf, false, 1);
    const dec = zlib(ob, true, 1);
    assert(isEqual(dec, buf));
});

test('deflate', function() {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    const ob = deflate(buf, false, 1);
    const dec = deflate(ob, true, 1);
    assert(isEqual(dec, buf));
});
import { Certificate } from "crypto";
import { read } from "fs";

test('certapi', () => {
    const CERT_PATH = import.meta.dirname + '/server.crt';

    const $c = new Certificate(read(CERT_PATH, true));
    console.log($c);
    
    // console.log($c.subject);
    // console.log($c.issuer);
    // console.log($c.status);
    // console.log($c.validRange);
    // console.log($c.next);

    assert($c.issuer === 'localhost');
    assert($c.subject === 'localhost');
    assert($c.status === 'ok');
    assert($c.validRange[0].year == 2025);
    assert($c.next() == null);
})

test('der-certapi', () => {
    const CERT_PATH = import.meta.dirname + '/server.der';

    const $c = new Certificate(read(CERT_PATH, false));
    console.log($c);

    assert($c.issuer === 'localhost');
    assert($c.subject === 'localhost');
    assert($c.status === 'ok');
    assert($c.validRange[0].year == 2025);
    assert($c.next() == null);
})
// timer
test('timer', function(){
    setTimeout(function(){
        console.log('setTimeout callback');
    }, 1000);
    setInterval(function(){
        console.log('setInterval callback');
    }, 3000);
    delay(2000).then(() => {
        console.log('delay callback');
    });
});

// atob/btoa
test('atob/btoa', function(){
    const str = 'Hello, World!';
    const encoded = btoa(str);
    const decoded = atob(encoded);
    console.log(encoded, decoded);
    console.assert(encoded != decoded, 'atob/btoa test failed');
});
// timer
test('timer', function(){
    setTimeout(function(){
        console.log('setTimeout callback');
    }, 1000);
    let ivcount = 0;
    const iv = setInterval(function(){
        console.log('setInterval callback');
        ivcount++;
        if(ivcount >= 3){
            clearTimer(iv);
        }
    }, 800);
    delay(2000).then( async() => {
        // for(let i=0; i<10; i++){
        //     await delay(1000);
        //     console.log(i);
        // }
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
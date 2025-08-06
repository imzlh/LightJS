// test('Event', async function(){
//     const evbus = new EventTarget();

//     const ev = new Event('test', {
//         cancelable: true,
//         detail: {
//             name: 'test'
//         }
//     });

//     test2('prevent', () => ev.preventDefault());

//     let trigged = false;
//     evbus.on('test', (event) => {
//         console.log(event);
//         trigged = true;
//     });

//     evbus.fire(ev);
//     assert(trigged, 'Event not triggered');
// });

test('globalBus', async () => {
    let trigged = false;
    events.on('unhandledrejection', (event) => {
        console.log('globalBus', event);
        trigged = true;
    });
    new Promise((rs, rj) => rj());
    await delay(1000)
    assert(trigged, 'globalBus not triggered');
})
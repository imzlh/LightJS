test('Event', async function(){
    const evbus = new EventTarget();

    const ev = new Event('test', {
        cancelable: true,
        detail: {
            name: 'test'
        }
    });

    test2('prevent', () => ev.preventDefault());

    evbus.on('test', (event) => {
        console.log(event.detail.name);
    });

    evbus.dispatch(ev);
});
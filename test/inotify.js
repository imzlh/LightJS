import { Inotify, unlink, write } from "fs"

test('inotify', () => {
    const ino = new Inotify(function(type, path, move_to){
        console.log(type, path, move_to);
    });

    ino.watch('/tmp/', Inotify.ALL_EVENTS);

    // touch some file
    write('/tmp/test.txt', 'test');
    unlink('/tmp/test.txt');
})
test('url', function(){
    let url = new URL('https://username:password@www.example.com/path/to/page.html?query=string#hash');
    assert(url.protocol === 'https:', 'url.protocol should be "https:"');
    assert(url.host === 'www.example.com', 'url.hostname should be "www.example.com"');
    assert(url.path === '/path/to/page.html', 'url.pathname should be "/path/to/page.html"');
    assert(url.query === '?query=string', 'url.search should be "?query=string"');
    assert(url.hash === '#hash', 'url.hash should be "#hash"');
    assert(url.getQuery('query') === 'string', 'url.getQuery("query") should be "string"');
    url.delQuery('query');
    assert(url.getQuery('query') === null, 'url.getQuery("query") should be null after deleting it');
    url.addQuery('query', 'new_string');
    assert(url.getQuery('query') === 'new_string', 'url.getQuery("query") should be "new_string" after adding it');
    assert(url.toString() === 'https://username:password@www.example.com/path/to/page.html?query=new_string#hash', 'url.toString() should be "https://username:password@www.example.com/path/to/page.html?query=new_string#hash"');
    assert(url.username === 'username', 'url.username should be "username"');
    assert(url.password === 'password', 'url.password should be "password"');
})
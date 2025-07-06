# LightJS
> 一个JavaScript运行环境，极度轻量化，简单又小巧

# 碎碎念
QuickJS真的好...比NodeJS这样基于v8的引擎小了一个数量级<br>
LightJS灵感起源于QuickGateway，失败后打算推翻quickjs-libc重写<br>
本来想要取TinyJS的(起名废)，发现TJS已经有了，于是就叫做LightJS了

# 为什么LightJS
 - 库全部使用C实现，二进制可执行文件中除了交互模式坚决不使用JS代码胶合
 - 极少的外部库依赖，甚至EventLoop和http服务器/客户端都是自己实现的
    - mbedtls(可选，可裁剪)
    - mimalloc(高性能必备，可选)
    - zlib(可选，大部分系统自带)
    - libexpat(可选，很多系统自带，非常轻量)
    - libffi(可选，很多系统自带)
 - 简单的API，少而优雅<br>
    拒绝反人类的`Response`(deno)，在LJS中可以链式处理请求！<br>
    `resp.status(200).write('data').header('A', 'b').end()`
 - 超高性能、超好用的U8Pipe，内置异步读行、读指定大小的数据、混合且支持用户拦截的pipeTo等功能，再也不需要手动截流啦
 - 超级简单的ffi，再也不用担心胶水代码比库代码还多的困难啦
 - 很多独创的功能，如
    - `Worker.interrupt()`强制终止当前执行的JS代码，对死循环立竿见影
    - `Sandbox.eval()`不会污染全局作用域，再也不需要危险的`with{}`了！
    - 原生linux shm、使用`new SharedMemory()`实现进程间共享内存！
    - ...

# 警告
LightJS还在萌芽，不确定是否能用（BUG会很多），希望大家参与进来，欢迎PR！
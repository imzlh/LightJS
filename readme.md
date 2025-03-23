# LightJS
> 一个JavaScript运行环境，极度轻量化，简单又小巧

# 碎碎念
QuickJS真的好...比NodeJS这样基于v8的引擎小了一个数量级<br>
LightJS灵感起源于QuickGateway，失败后打算推翻quickjs-libc重写<br>
本来想要取TinyJS的(起名废)，发现TJS已经有了，于是就叫做LightJS了

# 为什么LightJS
 - 库全部使用C实现，二进制可执行文件中除了交互模式不使用哪怕一行JS代码<br>
    我们的对手全部阵亡
 - 极少的外部库依赖，甚至EventLoop都是自己实现的<br>
    tokio、libuv...我们的对手全部阵亡
 - 简单的API，好用而不是迎合WebAPI<br>
    如反人类的`Response`，在LJS中可以链式处理！<br>
    `resp.status(200).write('data').header('A', 'b').end()`
 - ...

# 警告
LightJS还在萌芽，不确定是否能用（BUG会很多），希望大家参与进来，欢迎PR！
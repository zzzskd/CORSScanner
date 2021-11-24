 ### 一、CORS 跨域基础介绍
 
 分为简单请求、非简单请求
 
 1. 简单请求
    简单请求为浏览器自动加上 `Origin` 字段, 后端返回结果中包含：
       `Access-Control-Allow-Origin: origin_host or *`
       `Access-Control-Allow-Credentials: true`
       `Access-Control-Expose-Headers: response_header1, response_header2`
 2. 非简单请求
    浏览器发送预检请求，即发送 Request Method 为 `Options` 的请求, 如果预检通过，后续再发送**只**带 `Origin` header 的请求


 CORS 跨域漏洞的作用是其他域获取目标域的敏感信息, 敏感信息通常都是需要认证的, 所以我们需要判断 Response 中的
 `Access-Control-Allow-Credentials` 为 `true`, 而想让该字段生效，`Access-Control-Allow-Origin` 为恶意host, 不能为 `*`


 ### 二、CORS 跨域漏洞检测正常大致逻辑：

 1. 判断是Request Method 否是 `Options`, 如果是的话, 忽略
 2. 判断是否是简单请求
    1. 如果是简单请求
       1. 修改 `Origin` 字段为随机 host, 发送请求
       2. 判断 response 中的 `Access-Control-Allow-Origin` 和 `Access-Control-Allow-Credentials` 值
    2. 如果是非简单请求
       1. 发送 `OPTIONS` 请求, 主要添加 `Origin`、`Access-Control-Request-Method`、`Access-Control-Request-Headers` 字段
       2. 检查 Access-Control-Allow-Origin、 Access-Control-Allow-Methods、Access-Control-Allow-Credentials、
          `Access-Control-Allow-Headers` 值

 **但是** 实现过程中发现流量经过 burp 时已经被浏览器自动添加了一些字段，在判断是否是非简单请求中需要去除这些字段，由于没有找到浏览器会自动添加哪
 些字段，因此：为了方便起见, 我们知道非简单请求在发送预检请求之后, 每次请求中仍然带有 `Origin` 字段, 后端也只回复 `Access-Control-Allow-Origin`
 和 `Access-Control-Allow-Credentials`, 那么我们的检测逻辑：
 
 1. 修改/添加 `Origin` 字段
 2. 判断 `Access-Control-Allow-Origin` 和 `Access-Control-Allow-Credentials` 值
 
 
 另外，这里并不会跳过检查静态文件, 因为静态文件中可能会有用户的敏感信息, 比如 js 中可能会有 userId、userSessionID。


 ### 三、CORS 跨域漏洞跟 CSRF 的区别

 CSRF 对 header 要求更严格, 从而不会触发浏览器对跨域的检测, 可以发送一些请求, 但绕过不过浏览器的同源策略, 也就是只可以发送一些数据,
 但获取不了返回值(JSONP hijacking 除外).

 1. CSRF 是修改值的（JSONP Hijacking 除外）, CORS 跨域漏洞既可以修改值也可以获取值, 危害更大，但限制条件更多
 2. 首先 CSRF 肯定是个简单请求, 请求方法限制了 CSRF 只能是 GET、POST ( 简单请求中还允许 Head )
 3. 其次只允许提交 form 表单, 不能自定义header头, 只能根据 form 表单的 `entype` 设置 `Content-Type` 为 `application/x-www-form-urlencoded` (默认)、
    `multipart/form-data`、`text/plain`
    
 ### 四、错误的 Nginx 配置 
 
 ```
 location / {
        # First attempt to serve request as file, then
        # as directory, then fall back to displaying a 404.
        add_header Access-Control-Allow-Origin '$http_origin';
        add_header Access-Control-Allow-Credentials 'true';
        add_header Access-Control-Allow-Methods 'GET, POST, OPTIONS';
        add_header Access-Control-Allow-Headers 'Keep-Alive,X-R
 equested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization';

        if ($request_method = 'OPTIONS') {
           return 204;
        }
 }
 ```
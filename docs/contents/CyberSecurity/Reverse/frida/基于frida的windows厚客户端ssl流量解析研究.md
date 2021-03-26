# 基于frida的windows厚客户端ssl流量解析研究

> 作者：he0xwhale

在最近的windows厚客户端研究中，需要对该客户端的ssl加密信息进行解密，解密后才能对其web后端进行渗透测试。于是，在githubs上找到了ssl流量的解密工具[ssl_logger](https://github.com/google/ssl_logger/blob/master/ssl_logger.py)，但其是基于linux/darwin平台，所以将其修改为win平台。本文对ssl_logger的实现流程进行了分析，并借此机会学习了frida的基本使用方法。

修改之后的ssl_logger，我放在了github上：[ssl_logger](https://github.com/he0xwhale/ssl_logger.git)

# 说明

1. 本文系作者原创，欢迎转载，但请注明出处
2. 联系方式：he0xwhale@gmail.com
3. 特别感谢[Jason Geffner](https://github.com/geffner)共享的ssl_logger脚本
4. 作者也是frida的初学者，文章如果有错误或者纰漏，欢迎不吝赐教，共同学习进步

# ssl_logger安装及使用

## 安装

由于ssl_logger基于frida，所以首先需要安装frida，本文socket.inet_ntop使用的是python3，安装的frida版本为14

1. 安装frida

    ```shell
    pip install frida
    ```

    安装过程中，会遇到无法正常下载的问题，这里参考这篇文章[：安卓应用层协议/框架通杀抓包：实战篇](https://www.anquanke.com/post/id/228709)，主要问题在于pip下载的脚本中写死了pip源，手动修改为国内源后，可以正常下载

2. 安装frida-tools

    ```jsx
    pip install frida-tools
    ```

3. 安装hexdump

    如果要使用verbose显示详细流量信息，需要安装hexdump

    ```jsx
    pip install hexdump
    ```

4. 下载[ssl_logge](https://github.com/techbai/ssl_logger/blob/main/ssl_logger.py)r脚本，可以使用git下载

    ```python
    git clone https://github.com/techbai/ssl_logger.git
    ```

## 使用

这里假设需要分析的客户端二进制文件为**sample.exe**

1. 运行sample.exe
2. 运行ssl_logger:

    选项说明：

    - verbose:在控制台输出详细信息
    - pcap：将流量记录到pcap文件

    ```jsx
    python ssl_logger.py sample.exe -verbose -pcap sample.pcap
    ```

3. 对sample.exe进行相应的操作，结束后，在命令行界面**ctlr+z**结束ssl_logger
4. 使用wireshark打开pcap文件，会发现已经解密的流量
5. 可以使用burpsuite的repeater功能对流量重放，从而进行渗透测试

# ssl_logger如何工作

## 原理分析

ssl_logger主要通过frida对openssl库中的SSL_read() 和SSL_write()进行hook：

- 在收到服务端响应后，SSL_read()会将加密的流量读出来，这时，流量已经是解密的
- 在发送请求之前，SSL_write()会首先对流量进行加密，这时，就可以读取到明文的请求内容

## 基本流程分析

ssl_logger的基本流程如下：

![ssl_logger_workflow.png](https://image.3001.net/images/20210310/1615341183_6048267f02e43f1d78e4b.png)

### main流程分析

1. 解析命令行参数：
    - process：将要分析的进程
    - verbose：是否将详细内容输出到控制台
    - pcap：将要写入的pcap文件的名称

    ```python
      args = parser.add_argument_group("Arguments")
      args.add_argument("-pcap", metavar="<path>", required=False,
                        help="Name of PCAP file to write")
      args.add_argument("-verbose", required=False, action="store_const",
                        const=True, help="Show verbose output")
      args.add_argument("process", metavar="<process name | process id>",
                        help="Process whose SSL calls to log")
      parsed = parser.parse_args()
    ```

2. 调用`ssl_log` 方法，该方法是实现ssl流量记录的主方法

    ```jsx
    ssl_log(int(parsed.process) if parsed.process.isdigit() else parsed.process,
              parsed.pcap, parsed.verbose)
    ```

### `ssl_log` 方法流程分析

1. frida附加到将要分析的进程上，并返回session对象

    ```python
    	session = frida.attach(process)
    ```

2. 如果需要记录流量，则首先将pcap文件的文件头写入到指定的pcap文件中

    ```python
    if pcap:
        pcap_file = open(pcap, "wb", 0)
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=i", time.timezone),  # GMT to local correction
            ("=I", 0),              # Accuracy of timestamps
            ("=I", 65535),          # Max length of captured packets
            ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
          pcap_file.write(struct.pack(writes[0], writes[1]))
    ```

3. 创建javascript脚本，并将目标进程的`message`消息和`on_message` 方法进行关联，然后加载个该脚本。当进程有message消息发来的时候，就会回调`on_message`方法

    ```python
    script = session.create_script(_FRIDA_SCRIPT)
      script.on("message", on_message)
      script.load()
    ```

    - `_FRIDA_SCRIPT` 是javascript脚本，[随后分析]()
    - 这三句是firda的核心部分，frida通过回调的方式实现了对进程的hook
    - `on_message` 方法实现了回调的主要内容，[随后分析]()

4. 等待用户输入，如果用户输入了`ctlr+z` ，则取消对进程的附加；如果开启了pcap选项，则将pcap文件关闭（注意：如果没有正常关闭pcap文件，流量就不会被记录到文件中）

    ```python
    print("Press Ctrl+z to stop logging.")
      try:
        sys.stdin.read()
      except KeyboardInterrupt:
        print("KeyboardInterrupt")
        pass

      session.detach()
      if pcap:
        pcap_file.close()
    ```

### `_FRIDA_SCRIPT` 脚本分析

linux和windows平台上的差异主要体现在这个脚本上

1. initializeGlobals()

    初始化全局变量，并创建NativeFunction

    1. 初始化全局变量

        为了能够调用被attach程序中的Function，需要首先搜索到这些方法在内存中的地址，这里使用了`Module.findExportByName` 方法

        ```jsx
        var funcs=[
                  "SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
                      "SSL_SESSION_get_id","getpeername", "getsockname", "ntohs", "ntohl"
              ]
              funcs.forEach(function(f){
                  let address=Module.findExportByName(null,f)
                  addresses[f]=address
                  // console.log(f+" address:"+address)
              })
        ```

        - 需要调用的function如下：
            - [SSL_read](https://www.openssl.org/docs/man1.1.0/man3/SSL_read.html)：从SSL连接中读取指定字节的内容到缓存区buff
            - [SSL_write](https://www.openssl.org/docs/man1.1.0/man3/SSL_write.html)：从缓存区中读取指定字节的内容写入到SSL连接中
            - SSL_get_fd：获取指向SSL对象的文件描述符，用于后面获取IP和端口，具体参考官方文档：[SSL_get_fd](https://www.openssl.org/docs/man1.0.2/man3/SSL_get_fd.html)
            - SSL_get_session：返回在ssl对象中实际使用的SSL_SESSION对象，具体请参考[官方文档](https://www.openssl.org/docs/man1.1.0/man3/SSL_get_session.html)
            - SSL_SESSION_get_id：返回指定session对象的内部`session id` 值，具体请参考[官方文档](https://www.openssl.org/docs/man1.1.1/man3/SSL_SESSION_get_id.html)
            - [getpeername](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername#return-value)：返回socket的对端地址
            - [getsockname](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname)：返回指定socket描述符的当前名称
            - [ntohs](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ntohs)：将16位值由TCP/IP网络字节序转换为主机字节序
            - [ntohl](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ntohl)：将32位值由TCP/IP网络字节序转换为主机字节序
    2. 创建NativeFunction

        ```jsx
        SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int",
              ["pointer"]);
            SSL_get_session = new NativeFunction(addresses["SSL_get_session"],
              "pointer", ["pointer"]);
            SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"],
              "pointer", ["pointer", "pointer"]);
            getpeername = new NativeFunction(addresses["getpeername"], "int", ["int",
              "pointer", "pointer"]);
            getsockname = new NativeFunction(addresses["getsockname"], "int", ["int",
              "pointer", "pointer"]);
            ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
            ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
        ```

        - [NativeFunction](https://poxyran.github.io/poxyblog/src/pages/02-11-2019-calling-native-functions-with-frida.html#nativefunction)：该类允许创建一个代码内部指定地址的实际调用，其参数详解如下：
            - **address**: represents the actual address of the function we want to call. This parameter must be passed as a *NativePointer*
            - **returnType**: represents the return value returned by the function we want to call
            - **argTypes**: represent the arguments of the function we want to call. The supported types are the following: *void, pointer, int, uint, long, ulong, char, uchar, float, double, int8, uint8, int16, uint16, int32, uint32, int64, uint64 and bool*.
        - 具体可以参考：[Calling native functions with Frida](https://poxyran.github.io/poxyblog/src/pages/02-11-2019-calling-native-functions-with-frida.html#nativefunction)

2. 拦截器拦截`SSL_read` 和`SSL_write`
    1. 拦截器拦截`SSL_read` 

        ```jsx
        Interceptor.attach(addresses["SSL_read"],
          {
            onEnter: function (args)
            {
              var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
              message["ssl_session_id"] = getSslSessionId(args[0]);
              message["function"] = "SSL_read";
              this.message = message;
              this.buf = args[1];
            },
            onLeave: function (retval)
            {
              retval |= 0; // Cast retval to 32-bit integer.
              if (retval <= 0)
              {
                return;
              }
              send(this.message, Memory.readByteArray(this.buf, retval));
            }
          });
        ```

        - [Interceptor](https://frida.re/docs/javascript-api/?os_fayrUAIh9dZn4NQn2eYa_CHjS0MZILgw6_-Da98KgFCEyO0VFw0T7JosmZC1UxhFx_FXx6UtQAd_Pwbuf-qzAWkkHvq2MNbtG0jJhFUYPNwwgvHLGrvGzmpZR2hMCuZ9WS5-wfcR6FhRdk4gsnJNZHolnOk54CnnAbp-hop2ys3kF_hQ4KF8wyML-6XK-3yw8anlqoAWUKbpf9oZAiFJW4fZE2I4dzWvdpio97IrXb0sst_ezfWabAY1k2owVoZYFvhmbrybVsMjpHF29vmABidav0ogzOm47RO0AhXCw57OtMQN2LyGDyghQUN-iTGBoAejt4KoVTELhbjGPdBwicjmU_aC0LmtGw#interceptor).attach（target,callbacks[, data])）：通过拦截器的attach方法拦截`SSL_read` :
            - target：`SSL_read` 的地址
            - callbacks：该回调对象包含一个或者多个`onEnter` 和`onLeave` 方法
                - `onEnter` ：`SSL_read` 函数即将被调用之前，会回调该方法
                - `onLeave` ：`SSL_read` 函数返回之前，会回调该方法
        - `onEnter` ：获取`ssl_session_id` 以及收到的对端响应内容`buf`
            1. 获取文件描述符：`SSL_get_fd(args[0])` 
            2. 获取端口和IP地址：`getPortsAndAddresses` ，返回message对象。该方法为自定义方法，稍后分析
            3. 获取SslSessionId：`getSslSessionId(args[0])` ，该方法为自定义方法，稍后分析
            4. 指定message的`function` 值为`SSL_read` 
            5. 存储message以及buf，buf用于写入接收到的数据，:`this.buf = args[1];` 
        - `onLeave` ：
            1.  `SSL_read` 函数执行完成返回前，已经成功将SSL中的数据读到了buff中，再通过`send` 方法将`buf` 中`retval` （`SSL_read`函数的返回值为读取到的字节数）个字节的内容发送给调试进程（frida-based application :这里就是ssl_logger这个python脚本）。在`ssl_logger.py`中`on_message` 方法会接收到这里发出的消息
            2. 对返回值的处理：
                - 将`retval` 强制转换成32位整数： `retval |= 0; // Cast retval to 32-bit integer.`
                - 如果`retval` 小于0，表示数据读取失败，直接返回
            3. `Memory.readByteArray(address, length)` 方法：从地址`address` 处，读取length长度的内容
    2. 拦截器拦截`SSL_write` 

        ```jsx
        Interceptor.attach(addresses["SSL_write"],
          {
            onEnter: function (args)
            {
              var message = "Requests."
              var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
              message["ssl_session_id"] = getSslSessionId(args[0]);
              message["function"] = "SSL_write";
              send(message, Memory.readByteArray(args[1], parseInt(args[2])));
            },
            onLeave: function (retval){}
          }
        ```

        - `SSL_write` 函数执行之前，buf中的数据已经存在，所以只需要在进入该函数之后，就可以读取到buff中的内容，然后将其发送出去
        - `message` 当中包含的信息和拦截器对`SSL_read` 的处理一致

3. 其他方法

1. `getPortsAndAddresses` 方法
    - 作用：通过调用`getsockname` /`getpeername`获取端口和IP地址
    - 代码解析：

        ```jsx
        function getPortsAndAddresses(sockfd, isRead)
            {
        			//1
              var message = {};
        			//2
              var addrlen = Memory.alloc(4);
              var addr = Memory.alloc(16);
        			//3
              var src_dst = ["src", "dst"];
              for (var i = 0; i < src_dst.length; i++)
              {
                Memory.writeU32(addrlen, 16);
                if ((src_dst[i] == "src") ^ isRead)
                {
                  getsockname(sockfd, addr, addrlen);
                }
                else
                {
                  getpeername(sockfd, addr, addrlen);
                }
                message[src_dst[i] + "_port"] = ntohs(Memory.readU16(addr.add(2)));
                message[src_dst[i] + "_addr"] = ntohl(Memory.readU32(addr.add(4)));
              }
              return message;
            }
        ```

        1. 定义`message`:存储源地址/源端口以及目的地址/目的端口

            ```jsx
            var message = {};
            ```

        2. 由于`getsockname/getpeername(SOCKET s,sockaddr *name,int *namelen)` 的参数`sockaddr *name` 的类型为结构体`[sockaddr](https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2)` ，其长度为16个字节，所以需要在堆上申请相应大小的空间：

            ```jsx
            var addr = Memory.alloc(16);
            ```

            参数`namelen` 的类型为int，同理，需要申请4个字节大小的空间：

            ```jsx
            var addrlen = Memory.alloc(4);
            ```

        3. 接着就需要调用`getsockname` 和`getpeername` 得到`src_addr/src_port` 和`dst_addr` 和`dst_port` ，这里需要注意的有几点：
            - 传入的参数中，`addr` 是需要返回的`sockaddr`结构，其中包含IP和端口，只有`addrlen` 需要我们写入值，也就是`sockaddr` 结构的长度：16个字节。所以这里调用`Memory.writeU32` 写入`16` 。调用`writeU32`的的原因是，该参数类型为int。
            - `sockaddr_in` 结构的定义如下：

                ```cpp
                struct sockaddr_in {
                        short   sin_family;
                        u_short sin_port;
                        struct  in_addr sin_addr;
                        char    sin_zero[8];
                };
                ```

                1.  `sin_family` 类型为`short` ，[长度为16](https://en.cppreference.com/w/cpp/language/types) ；`sin_port` 类型为`u_short` ,长度为16；结构体`in_addr` 的大小为32字节。所以，读取端口的时候，需要将指针addr+2，然后使用`Memory.readU16` 读取：`Memory.readU16(addr.add(2))` 。因为`sin_port` 为网络字节序，所以需要调用`ntohs` 转换为主机字节序。
                2. 同理，读取IP时，需要将指针addr+4，然后使用`Memory.readU32` 读取：`Memory.readU32(addr.add(4))`

2. `getSslSessionId` 方法
    - 作用：获取SSL的sessionId
    - 代码分析：

        ```jsx
        function getSslSessionId(ssl)
        {
              var session = SSL_get_session(ssl);
              if (session == 0)
              {
                return 0;
              }
              var len = Memory.alloc(4);
              var p = SSL_SESSION_get_id(session, len);
              len = Memory.readU32(len);
              var session_id = "";
              for (var i = 0; i < len; i++)
              {
                // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
                // it to session_id.
                session_id +=
                  ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
              }
              return session_id;
            }
        ```

        1. 首先通过调用本地`SSL_get_session` 方法，获取到`SSL_SESSION` 对象`session` 

            ```jsx
            var session = SSL_get_session(ssl);
            ```

        2. 为了能够调用`SSL_SESSION_get_id` 方法，首先需要分配32字节（参数len的类型为int）的空间；然后调用该方法，得到返回值p（指向session_id的指针）；然后读取len指针指向的内容（`SSL_SESSION_get_id` 方法会将id的长度写入len中）

            ```jsx
            var len = Memory.alloc(4);
            var p = SSL_SESSION_get_id(session, len);
             len = Memory.readU32(len);
            ```

        3. 为了能够将session_id成功的读取出来，需要逐字节进行转换，然后进行拼接。对每个字节需要进行的处理：首先在指定位置读取8位比特`Memory.readU8(p.add(i))`，转换为16进制`toString(16)` ，然后转为为大写`toUpperCase()` ，在开头添加`"0"+` 之后，截取最后两位：`substr(-2)` 

### log_pcap方法流程分析

1. 该方法接收8个参数，分别为：
    - pcap_file: 打开的pcap文件
    - ssl_session_id: SSL会话的ID
    - function: 被拦截的方法("SSL_read" 或者 "SSL_write")
    - src_addr: 记录数据包的源地址
    - src_port: 记录数据包的源端口
    - dst_addr: 记录数据包的目的地址
    - dst_port: 记录数据包的目的端口
    - data: 解密包数据
2. 生成时间戳：`time.time()` ，这里的时间写入pacap文件的时间，不知道wireshark是怎么生成这个值的。这个值将会写入pacap文件的时间戳字段，其C结构体定义可以参考：[网络编程-pcap数据包格式](https://www.cnblogs.com/liang-hk/p/4063902.html)
3. 接着随机生成seq和ack，并存储到`ssl_sessions` 字典中（该变量为全局变量，在程序启动时已经初始化），依据`function` 是`SSL_read` 还是`SSL_write` 来对seq和ack赋值。这里的疑惑点是：为什么没有直接将原始数据读取出来保存，而是需要自己随机生成？当然，我们的关注点是解密后的SSL数据，所以，这里并不是关注的重点。有关seq和ack的解释可以参考：[TCP Sequence and Acknowledgement Numbers Explained](https://madpackets.com/2018/04/25/tcp-sequence-and-acknowledgement-numbers-explained/) 和[为什么三次握手的时候ack=seq+1](https://blog.csdn.net/oldfish_C/article/details/105150516)

    ```python
    if ssl_session_id not in ssl_sessions:
          ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                          random.randint(0, 0xFFFFFFFF))
        client_sent, server_sent = ssl_sessions[ssl_session_id]

        if function == "SSL_read":
         #这里的 client_sent+1是依据谋篇修改后的ssl_logger改的，原始代码为：client_sent。修改是否正确，值的商榷
          seq, ack = (server_sent, client_sent+1)
        else:
          seq, ack = (client_sent, server_sent)
    ```

4. 接着，将pcap的流量包头写入pcap文件中：
    - 其中涉及到了PCAP流量包头的格式，IPv4数据包头的格式，TCP数据包头的格式，具体赋值含义由于和SSL解密流量关系不大，这里先不进行分析
    - python的`struct` 模块用于将字节解析成打包的二进制数据，具体可以参考：[Interpret bytes as packed binary data](https://docs.python.org/3/library/struct.html)

    ```python
    for writes in (
            # PCAP record (packet) header
            ("=I", int(t)),                   # Timestamp seconds
            ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
            ("=I", 40 + len(data)),           # Number of octets saved
            ("=i", 40 + len(data)),           # Actual length of packet
            # IPv4 header
            (">B", 0x45),                     # Version and Header Length
            (">B", 0),                        # Type of Service
            (">H", 40 + len(data)),           # Total Length
            (">H", 0),                        # Identification
            (">H", 0x4000),                   # Flags and Fragment Offset
            (">B", 0xFF),                     # Time to Live
            (">B", 6),                        # Protocol
            (">H", 0),                        # Header Checksum
            (">I", src_addr),                 # Source Address
            (">I", dst_addr),                 # Destination Address
            # TCP header
            (">H", src_port),                 # Source Port
            (">H", dst_port),                 # Destination Port
            (">I", seq),                      # Sequence Number
            (">I", ack),                      # Acknowledgment Number
            (">H", 0x5018),                   # Header Length and Flags
            (">H", 0xFFFF),                   # Window Size
            (">H", 0),                        # Checksum
            (">H", 0)):                       # Urgent Pointer
          pcap_file.write(struct.pack(writes[0], writes[1]))
    ```

5. 将解密数据写入pcap文件：`pcap_file.write(data)` 
6. 为了使得seq和ack保持正确，需要将这两个值更新：

    ```python
    if function == "SSL_read":
          server_sent += len(data)
        else:
          client_sent += len(data)
    ssl_sessions[ssl_session_id] = (client_sent, server_sent)
    ```

### on_message方法流程分析

1. `on_message` 方法接收两个参数：
    - message：包含“type”和其他属性的**字典**，具体包含哪些属性，和message本身的类型有关
    - data：捕获到的加密数据字符串
2. 异常判断：
    - 首先判断是不是受到了error信息，如果收到了错误信息，就把错误信息输出，然后关闭掉当前进程（应该指的是ssl_logger的进程），然后返回

        ```python
        if message["type"] == "error":
              pprint.pprint(message)
              os.kill(os.getpid(), signal.SIGTERM)
              return
        ```

    - 如果返回的数据长度为0，同样返回到main

        ```python
            if len(data) == 0:
              return
        ```

3. 读取payload信息，并输出其详细内容

    ```python
    p = message["payload"]
        if verbose:
          src_addr = socket.inet_ntop(socket.AF_INET,
                                      struct.pack(">I", p["src_addr"]))
          dst_addr = socket.inet_ntop(socket.AF_INET,
                                      struct.pack(">I", p["dst_addr"]))
          print("SSL Session: " + p["ssl_session_id"])
          print ("[%s] %s:%d --> %s:%d" % (
              p["function"],
              src_addr,
              p["src_port"],
              dst_addr,
              p["dst_port"]))
          hexdump.hexdump(data)
          print()
    ```

    - payload中包含了多个属性值
        - `src_addr` ：源地址
        - `dst_addr` ：目的地址
        - `ssl_session_id` ：ssl的session_id
        - `function` ：javascript中hook掉的函数
        - `src_port` ：原端口
        - `dst_port` ：目的端口
    - 由于在payload中`src_addr`和`dst_addr` 的格式为类字节形式，所以需要调用`inet_ntop` 将格式转换为正常的IP格式，类似：`'7.10.0.5'`

        官方文档：

        `socket.**inet_ntop**`(*address_family*, *packed_ip*)[¶](https://docs.python.org/3/library/socket.html#socket.inet_ntop)

        Convert a packed IP address (a [bytes-like object](https://docs.python.org/3/glossary.html#term-bytes-like-object) of some number of bytes) to its standard, family-specific string representation (for example, `'7.10.0.5'` or `'5aef:2b::8'`). `[inet_ntop()](https://docs.python.org/3/library/socket.html#socket.inet_ntop)` is useful when a library or network protocol returns an object of type `struct in_addr` (similar to `[inet_ntoa()](https://docs.python.org/3/library/socket.html#socket.inet_ntoa)`) or `struct in6_addr`.

    - 使用hexdump的hexdump方法显示数据
4. 如果有pcap选项，则将内容输出到pcap文件

    ```python
    if pcap:
          src_addr = socket.inet_ntop(socket.AF_INET,
                                      struct.pack(">I", p["src_addr"]))
          dst_addr = socket.inet_ntop(socket.AF_INET,
                                      struct.pack(">I", p["dst_addr"]))
          log_pcap(pcap_file, p["ssl_session_id"], p["function"],  p["src_addr"],
                   p["src_port"], p["dst_addr"], p["dst_port"], data)
    ```

    - ~~这里同样调用了`inet_ntop` 方法转换IP格式，但是后面并没有调用，这里需要进一步确认原因~~ （这里属于多余代码，删除即可）
    - 通过调用`log_pcap`方法来记录流量文件，[稍后分析该方法]()

# 进一步思考

## 存在的不足/bug

1. 读取到的IP和端口都是0，原因未知，需要进一步分析

## 更多的feature

1. 现在只是将ssl解密流量记录下来，如果要更方便的进行渗透测试，最好是可以将流量重定向到类似burpsuite这样的工具中，提高测试效率
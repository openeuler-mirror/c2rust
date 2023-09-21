 ## 使用 safer-c2rust 转换 urlparser

1. 本测试中，选用的是`0.2.1`版本，可以通过执行以下以命令获取C源码：
    
    ```shell
    git clone --depth=1 --branch 0.2.1  https://github.com/jwerle/url.h.git
    ```

2. 在项目根目录下运行：

    ```
    python3 run.py c2rust -c examples/urlparser/url.h  --gencc=makefile safer stat
    ```


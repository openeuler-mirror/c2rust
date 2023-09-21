## 使用 safer-c2rust 转换 JsonC

1. 本测试中，选用的是`release-0.15`版本，可以通过执行以下以命令获取C源码：
    
    ```shell
    git clone --branch json-c-0.15-20200726  https://github.com/json-c/json-c.git
    ```

2. 在项目根目录下运行：

    ```
    python3 run.py c2rust -c examples/jsonc/json-c safer stat
    ```


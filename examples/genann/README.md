 ## 使用 safer-c2rust 转换 genann

1. 本测试中，选用的是`v1.0.0`版本，可以通过执行以下以命令获取C源码：

    ```shell
    git clone --depth=1 --branch v1.0.0  https://github.com/codeplea/genann.git
    ```

2. 在项目根目录下运行：

    ```shell
    python3 run.py c2rust --local_path path/to/genann safer stat
    ```

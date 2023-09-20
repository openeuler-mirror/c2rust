## 使用 safer-c2rust 转换 curl

1. 本测试中，选用的是`v7.79.1`版本，可以通过执行以下以命令获取C源码：
    
    ```shell
    git clone --depth=1 --branch curl-7_79_1  https://github.com/curl/curl.git
    ```

2. 安装前置依赖：
    - ubuntu/debian
    ```shell
    
    ```
    - centos/openEuler
    ```shell
    ```


3. 在项目根目录下运行：

    ```
    python3 run.py c2rust -c examples/curl/curl --mode="script" --script examples/curl/translate.sh safer stat
    ```

## 使用 safer-c2rust 转换 grbc

1. 通过执行以下以命令获取C源码：

    ```shell
    git clone https://github.com/immunant/grabc.git
    ```

2. 安装依赖：

    - `ubuntu`/`debian`

    ```shell
    sudo apt install libx11-dev
    ```

    - `openEuler`/`CentOS`

    ```shell
    sudo yum install libX11-devel
    ```

3. 在项目根目录下运行：

    ```shell
    python3 run.py c2rust --local_path path/to/grabc/ safer stat
    ```

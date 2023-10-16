 ## 使用 safer-c2rust 转换 libxml2

本测试中，选用的是`openEuler-22.03-LTS-SP1`上默认libxml2版本，运行命令如下：

```shell
python3 run.py c2rust --src osc --project_name libxml2 --osc_branch openEuler-22.03-LTS-SP1 safer stat
```

> 根据运行环境，运行时间可能需要2~3个小时

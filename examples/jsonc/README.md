## 使用 safer-c2rust 转换 Json-c

本测试中，选用的是`openEuler-22.03-LTS-SP1`上默认jsonc版本，运行命令如下：

```shell
python3 run.py c2rust --src osc --project_name json-c --osc_branch openEuler-22.03-LTS-SP1 --mode auto --gencc cmake safer stat
```


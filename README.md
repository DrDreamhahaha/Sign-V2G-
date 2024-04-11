# Sign-V2G-
这是对V2G的实体仿真，使用python实现

## 对于src
这是主体的实现部分，你需要运行run.py查看实验数据
suclass.py的函数是实现V2G实体类的地方，分为MV电动车，MC充电电桩，Authority权威机构，EdgeNode是边缘节点
private.py是实现私钥生成的函数

## 对于test
你可以不用管它，这里是放错误和测试函数的地方

## 环境说明
requirements.txt 是我的各种python依赖库的版本
如果你运行setup.py设置好依赖后，无法运行程序，你需要对照requirements.txt的版本下载
项目的编译器是python3.11注意编译器版本，python编译器不向下兼容

# 白盒GCM模式

#### 目前支持算法

- aes
- 白盒aes

#### 目前支持加密模式

- GCM模式
- 白盒GCM模式 - WBGCM-EE, WBGCM-Masking


## 构建 && 安装

### 快速开始

请确保编译环境中含gcc和cmake环境，在当前目录下快速编译：

```
$ mkdir build && cd build
$ cmake ..
$ make
```

目录{项目路径}/build/out目录下为头文件和编译库，和测试文件。

（可选）使用下面命令将头文件和编译库安装至系统全局环境中：

```
$ sudo make install
```

假设创建测试文件test.c调用环境变量中的wbcrypto编译库，请指定动态库搜索路径，例如ubuntu环境下：

```
$ gcc test.c -o test -lwbcrypto -Wl,-rpath="/usr/local/lib
```

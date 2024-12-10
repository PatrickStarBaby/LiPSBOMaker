# SLP

SLP是一个针对Linux发行版的SBOM生成工具，可以生成多粒度多阶段的SBOM



### 一、命令总览

```bash
slp version
slp image [SOURCE] --output=[Filename]
slp package --lifecycle=["source"/"release"/"installed"] [SOURCE] --output=[Filename]
```



### 二、不同需求对应的命令：

#### Linux发行版粒度

```bash
slp image [镜像名] --output=[输出的SBOM文件]
```



#### Linux软件包粒度

##### 源码包阶段：

```bash
#rpm源码阶段，传入rpm源码包路径
slp package -l=source "xxx.src.rpm" --output ./rpm-source.json

#deb源码包阶段（解压源码包后，将.dsc文件移入主文件夹，然后输入.dsc文件的路径）
slp package -l=source "xxx.dsc" --output ./deb-source.json
```

##### 二进制发行阶段：

```bash
#rpm二进制发行阶段，传入rpm二进制包路径
slp package -l=release "xxx.rpm" --output ./rpm-release.json

#deb二进制发行阶段，传入deb二进制包路径
slp package -l=release "xxx.deb" --output ./deb-release.json
```

##### 二进制使用阶段：

注意因为解析本地安装的软件包，所以需要依赖于本地环境，要在本地环境命令行中运行相关命令

```bash
#rpm二进制使用阶段，传入要解析的rpm软件包名
slp package -l=installed "xxx" --output ./rpm-installed.json

#deb二进制使用阶段，传入deb软件包名
slp package -l=installed "xxx" --output ./deb-installed.json
```


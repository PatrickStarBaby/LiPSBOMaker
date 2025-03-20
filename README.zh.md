# LiPSBOMaker

LiPSBOMaker是一个针对Linux发行版的SBOM生成工具，可以为Linux软件包生成多阶段的SBOM，包含源码阶段、发布阶段、使用阶段

[English]: README.md

 

### 一、命令总览

```bash
slp version
slp image [SOURCE] --output=[Filename]
slp package --lifecycle=["source"/"release"/"installed"] [SOURCE] --output=[Filename]
slp record [SOURCE]
```



### 二、不同需求对应的命令：

#### 生成SBOM

##### 源码包阶段：

```bash
#rpm源码阶段，传入rpm源码包路径
slp package -l=source "xxx.src.rpm" --output ./rpm-source.json

#deb源码包阶段（解压源码包后，将.dsc文件移入主文件夹，然后输入.dsc文件的路径，例/apt-2.7.14build2/apt_2.7.14build2.dsc）
slp package -l=source "xxx/xxx.dsc" --output ./deb-source.json
```

##### 二进制发布阶段：

```bash
#rpm二进制发布阶段，传入rpm二进制包路径
slp package -l=release "xxx.rpm" --output ./rpm-release.json

#deb二进制发布阶段，传入deb二进制包路径
slp package -l=release "xxx.deb" --output ./deb-release.json
```

##### 二进制使用阶段：

注意因为解析本地安装的软件包，所以需要依赖于本地环境，要在本地环境命令行中运行相关命令

```bash
#rpm二进制使用阶段，传入要解析的rpm软件包名，例如要生成本地bash软件包的SBOM,xxx直接就是bash
slp package -l=installed xxx --output ./rpm-installed.json

#deb二进制使用阶段，传入deb软件包名
slp package -l=installed xxx --output ./deb-installed.json
```



#### 记录构建环境信息：

记录构建环境信息的命令只有一个参数，即rpm源码包路径，或者deb源码包的.dsc文件路径

记录的构建环境信息输出会以固定的名字“buildEnv.json”保存到执行当前命令的路径下

```bash
#rpm体系，传入rpm源码包的路径，例如./dnf-4.16.2-3.oe2403.src.rpm
#deb体系，传入deb源码包的.dsc文件路径，例如./apt_2.7.14build2.dsc
slp record xxx
```

### 三、最佳实践

#### 1、对于RPM体系：

我们以dnf软件包为例，演示LiPSBOMaker在rpm体系中的最佳实践

##### ①下载源码包

```bash
dnf download --source dnf
```

得到dnf-4.16.2-6.oe2403.src.rpm源码包

##### ②生成dnf源码阶段SBOM

```bash
slp package -l=source ./dnf-4.16.2-6.oe2403.src.rpm --output ./dnf-source-SBOM.json
```

得到dnf源码阶段SBOM：dnf-source-SBOM.json（之后可以将源码阶段SBOM嵌入到dnf源码包中一起发布）

##### ③记录dnf源码包构建为二进制包过程中的编译环境信息

编译环境信息记录的整体流程：

①dnf源码包安装构建依赖、编译

②使用LiPSBOMaker工具，将dnf构建过程中所使用的构建依赖信息记录到buildEnv.json文件中

③将buildEnv.json文件嵌入到dnf二进制发布包中随其一起发布

④用户在下载到该dnf二进制发布包后，可以使用LiPSBOMaker扫描该二进制包，生成二进制使用阶段的SBOM，其中会对源码阶段使用的构建依赖信息进行补充。



**下面我们逐一介绍所使用到的命令：**

准备构建环境

```bash
#安装必要的构建工具
sudo yum install rpm-build rpmdevtools
#设置RPM构建环境
rpmdev-setuptree
```

解压dnf源码包，并将源代码等文件放入到`SOURCES` 目录，将.spec文件放入`SPECS`目录

```bash
#解压dnf源码包
rpm2cpio dnf-4.16.2-6.oe2403.src.rpm | cpio -idmv
cd SPECS
```

安装dnf所需要的构建依赖，之后使用LiPSBOMaker记录构建依赖的详细信息,将生成的buildEnv.json文件移入SOURCES目录以便后续打包

```bash
#安装构建依赖
dnf builddep dnf.spec
slp record dnf-4.16.2-6.oe2403.src.rpm
mv buildEnv.json ./SOURCES
```

修改dnf.spec文件，控制构建过程将buildEnv.json文件嵌入到最终生成的dnf二进制包中

```bash
#将buildEnv.json加入spec文件的Source配置
Source1:  buildEnv.json
#在%install段中增加添加buildEnv.json的文件的命令
mkdir -p %{buildroot}/usr/share/SBOM/
cp %{SOURCE1} %{buildroot}/usr/share/SBOM/
#在%files段添加以下内容，确保在构建过程中能够将buildEnv.json文件被包含在最终的二进制RPM包中：
/usr/share/SBOM/buildEnv.json
```

构建RPM包

```bash
rpmbuild -ba dnf.spec
```

生成的二进制包会存放在RPMS文件夹中，可以进行解压验证

确认无误之后便可发布该dnf二进制包

##### ④生成dnf二进制发布阶段SBOM

在下载到嵌入了buildEnv.json文件的二进制发布包后，使用LiPSBOMaker生成二进制发布阶段SBOM

```bash
slp package -l=release dnf-4.16.2-6.noarch.rpm --output ./dnf-release-SBOM.json
```

##### ⑤生成dnf二进制使用阶段SBOM

安装完dnf后，可以使用LiPSBOMaker生成二进制使用阶段SBOM

```bash
slp package -l=installed dnf --output ./dnf-installed-SBOM.json
```



#### 2、对于Deb体系：

这里以apt软件包为例

##### ①下载源码包

```bash
apt source apt
```

执行命令后，会在本地下载apt-2.7.14build2  apt_2.7.14build2.dsc  apt_2.7.14build2.tar.xz 三个文件

##### ②生成apt源码阶段SBOM

将.dsc文件拷贝到主目录apt-2.7.14build2

```bash
cp apt_2.7.14build2.dsc ./apt-2.7.14build2
```

使用LiPSBOMaker生成源码阶段SBOM

```bash
slp package -l=source apt-2.7.14build2/apt_2.7.14build2.dsc --output ./apt-source-SBOM.json
```

##### ③记录apt源码包构建信息

```bash
apt install dpkg-dev build-essential #安装必要的工具
apt-get build-dep apt #下载构建依赖项
slp record apt_2.7.14build2.dsc #记录构建依赖的详细信息
```

得到了buildEnv.json文件之后，将其拷贝到`源码主文件夹/debian/`中

```bash
cp buildEnv.json apt-2.7.14build2/debian/
```

修改源码包的install文件，在打包过程中将buildEnv.json文件添加到生成的apt二进制包中

```bash
#在apt-2.7.14build2/debian/apt.install文件中添加以下配置
debian/buildEnv.json /usr/share/SBOM/buildEnv.json
```

进入到源码主目录，开始构建二进制包

```bash
cd apt-2.7.14build2
dpkg-buildpackage -us -uc 
```

在上层目录就能得到构建出来的二进制包apt_2.7.14build2_amd64.deb，可以解压该二进制包验证文件是否成功嵌入

```bash
 dpkg-deb -x apt_2.7.14build2_amd64.deb apt  #解压.deb文件到本地apt文件夹
```

验证无误后可以发布该apt二进制包

##### ④生成apt二进制发布阶段SBOM

下载嵌入buildEnv.json文件的apt二进制包后，直接用命令生成SBOM

```bash
slp package -l=release apt_2.7.14build2_amd64.deb --output ./apt-release-SBOM.json
```

##### ⑤生成apt二进制使用阶段SBOM

安装完apt后，可以使用LiPSBOMaker生成二进制使用阶段SBOM

```bash
slp package -l=installed apt --output ./apt-installed-SBOM.json
```


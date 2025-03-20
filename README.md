# LiPSBOMaker

**LiPSBOMaker** is an SBOM generation tool for Linux distributions that can generate multi-stage SBOMs for Linux packages, including the source stage, release stage, and usage stage.

[中文文档]: README.zh.md
[点击这里](README.zh.md)


### 1. Command Overview

```bash
slp version
slp package --lifecycle=["source"/"release"/"installed"] [SOURCE] --output=[Filename]
slp record [SOURCE]
```



### 2. Commands for Different Requirements

#### (1) Generate SBOM

##### Source stage：

```bash
#For the RPM source stage, provide the path to the RPM source package.
slp package -l=source "xxx.src.rpm" --output ./rpm-source.json

#For the DEB source package stage (after extracting the source package, move the .dsc file to the main folder, then provide the path of the .dsc file, e.g., /apt-2.7.14build2/apt_2.7.14build2.dsc).
slp package -l=source "xxx/xxx.dsc" --output ./deb-source.json
```

##### Release stage：

```bash
#For the RPM release stage, provide the path to the RPM binary package.
slp package -l=release "xxx.rpm" --output ./rpm-release.json

#For the DEB release stage, provide the path to the DEB binary package.
slp package -l=release "xxx.deb" --output ./deb-release.json
```

##### Usage stage：

Please note that since the parsing of locally installed packages is dependent on the local environment, it is necessary to execute the relevant commands within the command line of the local environment.

```bash
#For the RPM usage stage, provide the name of the RPM package to be analyzed. For example, to generate the SBOM for the local bash package, simply use bash.
slp package -l=installed xxx --output ./rpm-installed.json

#For the DEB usage stage, provide the name of the DEB package.
slp package -l=installed xxx --output ./deb-installed.json
```



#### (2) Record build environment information

The command to record build environment information has only one parameter, which is either the path to the RPM source package or the path to the `.dsc` file of the DEB source package.

The recorded build environment information will be saved with the fixed name **`buildEnv.json`** in the current directory where the command is executed.

```bash
#For the RPM system, provide the path to the RPM source package, for example, ./dnf-4.16.2-3.oe2403.src.rpm.
#For the DEB system, provide the path to the .dsc file of the DEB source package, for example, ./apt_2.7.14build2.dsc.
slp record xxx
```



### 3. Best Practices

#### (1). For the RPM system:

Let's take the `dnf` package as an example to demonstrate the best practices of using LiPSBOMaker in the RPM system.

##### ① Download the source package.

```bash
dnf download --source dnf
```

get the **`dnf-4.16.2-6.oe2403.src.rpm`** source package.

##### ② Generate the SBOM for the DNF source stage.

```bash
slp package -l=source ./dnf-4.16.2-6.oe2403.src.rpm --output ./dnf-source-SBOM.json
```

The dnf source stage SBOM **`dnf-source-SBOM.json`** has been generated (it can later be embedded into the dnf source package for distribution).

##### ③ Record the build environment information for the dnf source package during the process of compiling it into a binary package.

The overall process for recording the build environment information is as follows:

- Install the build dependencies for the DNF source package.

- Use the LiPSBOMaker tool to record the build dependencies information used during the DNF build process into the **`buildEnv.json`** file.

- Embed the **`buildEnv.json`** file into the DNF binary release package and release it together.

- After the user downloads the DNF binary release package, they can use the LiPSBOMaker tool to scan the binary package and generate the SBOM for the binary usage stage. This will supplement the build dependency information used in the source stage.



**Next, we will introduce the commands used one by one:**

Prepare the build environment:

```bash
#Install the necessary build tools.
sudo yum install rpm-build rpmdevtools
#Set up the RPM build environment.
rpmdev-setuptree
```

Extract the DNF source package, and place the source code and other files into the **`SOURCES`** directory, while placing the **`.spec`** file into the **`SPECS`** directory:

```bash
#Extract the DNF source package.
rpm2cpio dnf-4.16.2-6.oe2403.src.rpm | cpio -idmv
cd SPECS
```

Install the build dependencies required by DNF. Afterward, use LiPSBOMaker to record the detailed build dependencies information. Move the generated **`buildEnv.json`** file into the **`SOURCES`** directory for later packaging:

```bash
#Install the build dependencies.
dnf builddep dnf.spec
slp record dnf-4.16.2-6.oe2403.src.rpm
mv buildEnv.json ./SOURCES
```

Modify the **`dnf.spec`** file to control the build process and embed the **`buildEnv.json`** file into the final generated DNF binary package:

```bash
#Add the buildEnv.json file to the Source section of the .spec file.
Source1:  buildEnv.json
#Add the command to include the buildEnv.json file in the %install section.
mkdir -p %{buildroot}/usr/share/SBOM/
cp %{SOURCE1} %{buildroot}/usr/share/SBOM/
#Add the following content to the %files section to ensure that the buildEnv.json file is included in the final binary RPM package during the build process:
/usr/share/SBOM/buildEnv.json
```

Build the RPM package:

```bash
rpmbuild -ba dnf.spec
```

The generated binary package will be stored in the **RPMS** folder, and you can extract it to verify.

Once confirmed to be correct, the DNF binary package can be released.

##### ④ Generate the SBOM for the DNF release stage.

After downloading the binary release package with the embedded **`buildEnv.json`** file, use LiPSBOMaker to generate the SBOM for the binary release stage.

```bash
slp package -l=release dnf-4.16.2-6.noarch.rpm --output ./dnf-release-SBOM.json
```

##### ⑤ Generate the SBOM for the DNF usage stage.

After installing DNF, you can use LiPSBOMaker to generate the SBOM for the binary usage stage.

```bash
slp package -l=installed dnf --output ./dnf-installed-SBOM.json
```



#### (2) For the DEB system:

Here, we will use the **apt** package as an example.

##### ① Download the source package.

```bash
apt source apt
```

After executing the command, the following three files will be downloaded locally: `apt-2.7.14build2`  `apt_2.7.14build2.dsc`  `apt_2.7.14build2.tar.xz`

##### ② Generate the SBOM for the apt source stage.

Copy the **`.dsc`** file to the main directory **`apt-2.7.14build2`**:

```bash
cp apt_2.7.14build2.dsc ./apt-2.7.14build2
```

Use LiPSBOMaker to generate the SBOM for the source stage:

```bash
slp package -l=source apt-2.7.14build2/apt_2.7.14build2.dsc --output ./apt-source-SBOM.json
```

##### ③ Record the build information for the apt source package.

```bash
apt install dpkg-dev build-essential #Install the necessary tools.
apt-get build-dep apt #Download the build dependencies.
slp record apt_2.7.14build2.dsc #Record the detailed information of the build dependencies.
```

After obtaining the **`buildEnv.json`** file, copy it to the **`/debian/`** folder in the source main directory:

```bash
cp buildEnv.json apt-2.7.14build2/debian/
```

Modify the **`install`** file of the source package to include the **`buildEnv.json`** file in the generated apt binary package during the packaging process:

```bash
#Add the following configuration to the apt-2.7.14build2/debian/apt.install file:
debian/buildEnv.json /usr/share/SBOM/buildEnv.json
```

Enter the source main directory and begin building the binary package:

```bash
cd apt-2.7.14build2
dpkg-buildpackage -us -uc 
```

In the upper directory, you will find the built binary package **`apt_2.7.14build2_amd64.deb`**. You can extract this binary package to verify if the file has been successfully embedded:

```bash
 dpkg-deb -x apt_2.7.14build2_amd64.deb apt  #Extract the .deb file to the local apt folder.
```

Once verified, the **apt** binary package can be released.

##### ④ Generate the SBOM for the apt release stage.

After downloading the apt binary package with the embedded **`buildEnv.json`** file, directly use the command to generate the SBOM:

```bash
slp package -l=release apt_2.7.14build2_amd64.deb --output ./apt-release-SBOM.json
```

##### ⑤ Generate the SBOM for the apt usage stage.

After installing apt, you can use LiPSBOMaker to generate the SBOM for the binary usage stage:

```bash
slp package -l=installed apt --output ./apt-installed-SBOM.json
```


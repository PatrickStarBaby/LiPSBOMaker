package _package

import "github.com/CycloneDX/cyclonedx-go"

type LifecycleType string

const (
	SourceLifecycle    LifecycleType = "source"
	ReleaseLifecycle   LifecycleType = "release"
	InstalledLifecycle LifecycleType = "installed"
)

type Metadata struct {
	Lifecycle   LifecycleType `json:"lifecycle,omitempty"`
	BomRef      string        `json:"bom-ref,omitempty"` //扫描对象的bomref
	Name        string        `json:"name,omitempty"`
	Version     string        `json:"version,omitempty"`
	Release     string        `json:"release,omitempty"` //rpm包的release
	PURL        string        `json:"purl,omitempty"`
	CPE         string        `json:"cpe,omitempty"`
	Url         string        `json:"url,omitempty"` //扫描对象的链接
	Description string        `json:"description,omitempty"`

	/* 源码包特有的元数据 */
	Sources            []string `json:"sources,omitempty"` //源码包含的关键文件
	License            []string `json:"license,omitempty"`
	Copyright          string   `json:"copyright,omitempty"`
	Maintainer         string   `json:"maintainer,omitempty"`         //维护者信息
	OriginalMaintainer string   `json:"originalMaintainer,omitempty"` //上游维护者信息
	PackageList        string   `json:"packageList,omitempty"`        //由该源码包构建出的所有的二进制包列表
	IsNative           string   `json:"isNative,omitempty"`           //是否为原生包
	Architecture       string   `json:"architecture,omitempty"`       //源码包针对的架构

	/* 二进制包特有的元数据 */
	SourcePkg string `json:"source_pkg,omitempty"` //构建出该二进制包的源码包
	Packager  string `json:"packager,omitempty"`   //打包者信息
	BuildTime string `json:"buildTime,omitempty"`  //构建时间
	BuildHost string `json:"buildHost,omitempty"`  //构建的主机
	Section   string `json:"section,omitempty"`    //deb包属于的类型
	Priority  string `json:"priority,omitempty"`   //deb包的Priority字段
}

type Patch struct {
	BomRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name,omitempty"` //补丁文件的名称
	From    string `json:"from,omitempty"`
	Date    string `json:"date,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// Linux内核
type LinuxKernel struct {
	Name         string `json:"name,omitempty"`         //内核名称
	Version      string `json:"version,omitempty"`      //内核版本，例如5.15.167.4-microsoft-standard-WSL2
	BomRef       string `json:"bom-ref,omitempty"`      //扫描对象的bomref
	Architecture string `json:"architecture,omitempty"` //内核针对的架构
	BuildTime    string `json:"buildTime,omitempty"`    //内核编译的时间
	Compiler     string `json:"compiler,omitempty"`     //编译该内核的编译器信息
}

// 运行时依赖
type Depend struct {
	Metadata
	DebDependType string `json:"debDependType,omitempty"` //Built-Using、Depends、Pre-Depends
	RpmRequire    string `json:"rpmRequire,omitempty"`    //指明主包依赖于该包提供的哪个功能
}

type BuildDepend struct {
	Metadata
	DebBuildDependType       string `json:"debBuildDependType,omitempty"`            //deb的构建依赖类型：Build-Depends、Build-Depends-Indep、Build-Depends-Arch
	AffectsBinaryComposition bool   `json:"affectsBinaryComposition,omitempty"`      //是否会直接影响（成为）二进制包的成分
	InferentialDescription   string `json:"inferential_description,omitempty"`       //用大模型生成分类时的推断性描述，记录以便校验
	VirtualOrConcreteDesc    string `json:"virtualOrConcrete_description,omitempty"` //这是虚实依赖描述
	RpmRequire               string `json:"rpmRequire,omitempty"`                    //指明主包依赖于该包提供的哪个功能
}

type Pkg struct {
	Metadata     *Metadata
	Depends      *[]Depend
	BuildDepends *[]BuildDepend
	Patches      *[]Patch
	Dependencies *[]cyclonedx.Dependency
}

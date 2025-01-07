package cyclonedxjson

import (
	"fmt"
	_package "slp/package"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

func ToFormatModel(s *_package.Pkg) *cyclonedx.BOM {
	cdxBOM := cyclonedx.NewBOM()

	// NOTE(jonasagx): cycloneDX requires URN uuids (URN returns the RFC 2141 URN form of uuid):
	// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json#L36
	// "pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	cdxBOM.SerialNumber = uuid.New().URN()
	cdxBOM.Metadata = encodeMetadata(s)

	cdxBOM.Components = encodeComponents(s)

	if s.Dependencies != nil {
		cdxBOM.Dependencies = s.Dependencies
	}

	return cdxBOM
}

func encodeMetadata(p *_package.Pkg) *cyclonedx.Metadata {
	var metadata cyclonedx.Metadata

	metadata.Timestamp = time.Now().Format(time.RFC3339)
	metadata.Tools = &cyclonedx.ToolsChoice{
		Components: &[]cyclonedx.Component{
			{
				Type:    cyclonedx.ComponentTypeApplication,
				Name:    "SLP",
				Version: "1.0",
			},
		},
	}

	switch p.Metadata.Lifecycle {
	case _package.SourceLifecycle:
		lifecycle := cyclonedx.Lifecycle{Name: string(_package.SourceLifecycle), Phase: cyclonedx.LifecyclePhasePreBuild, Description: "This is the source package stage."}
		metadata.Lifecycles = &[]cyclonedx.Lifecycle{lifecycle}
	case _package.ReleaseLifecycle:
		lifecycle := cyclonedx.Lifecycle{Name: string(_package.ReleaseLifecycle), Phase: cyclonedx.LifecyclePhasePostBuild, Description: "This is the stage for releasing the binary package after the source package has been built."}
		metadata.Lifecycles = &[]cyclonedx.Lifecycle{lifecycle}
	case _package.InstalledLifecycle:
		lifecycle := cyclonedx.Lifecycle{Name: string(_package.InstalledLifecycle), Phase: cyclonedx.LifecyclePhaseOperations, Description: "This is the stage for using the binary after it has been installed locally."}
		metadata.Lifecycles = &[]cyclonedx.Lifecycle{lifecycle}
	}

	properties := getMetadataComponentProperties(p.Metadata)
	metadata.Component = &cyclonedx.Component{
		BOMRef:             p.Metadata.BomRef,
		Type:               cyclonedx.ComponentTypeApplication,
		Name:               p.Metadata.Name,
		Version:            p.Metadata.Version,
		Copyright:          p.Metadata.Copyright,
		PackageURL:         p.Metadata.PURL,
		ExternalReferences: encodeExternalReferences(p.Metadata.Url),
		Licenses:           encodeLicenses(p.Metadata.License),
		Description:        p.Metadata.Description,
		Properties:         properties,
	}

	return &metadata
}

func encodeComponents(p *_package.Pkg) *[]cyclonedx.Component {
	var components []cyclonedx.Component
	if p.Depends != nil {
		for _, p := range *p.Depends {
			components = append(components, DependToComponent(p))
		}
	}
	if p.BuildDepends != nil {
		for _, p := range *p.BuildDepends {
			components = append(components, BuildDependToComponent(p))
		}
	}
	if p.Patches != nil {
		for _, p := range *p.Patches {
			components = append(components, PatchToComponent(p))
		}
	}

	return &components
}

func DependToComponent(p _package.Depend) cyclonedx.Component {
	var version string
	if p.Version == "" {
		version = "[not provided]"
	} else {
		version = p.Version
	}
	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeApplication,
		Name:       p.Name,
		Version:    version,
		PackageURL: p.PURL,
		Licenses:   encodeLicenses(p.License),

		//CPE:                encodeSingleCPE(p),
		//Author:             encodeAuthor(p),
		//Publisher:          encodePublisher(p),
		Description:        p.Description,
		ExternalReferences: encodeExternalReferences(p.Url),
		BOMRef:             p.BomRef,
		Properties:         getDependProperties(&p),
	}
}

func BuildDependToComponent(p _package.BuildDepend) cyclonedx.Component {
	var version string
	if p.Version == "" {
		version = "[not provided]"
	} else {
		version = p.Version
	}
	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeApplication,
		Name:       p.Name,
		Version:    version,
		PackageURL: p.PURL,
		Licenses:   encodeLicenses(p.License),
		//CPE:                encodeSingleCPE(p),
		//Author:             encodeAuthor(p),
		//Publisher:          encodePublisher(p),
		Description:        p.Description,
		ExternalReferences: encodeExternalReferences(p.Url),
		BOMRef:             p.BomRef,
		Properties:         getBuildDependProperties(&p),
	}
}

func PatchToComponent(p _package.Patch) cyclonedx.Component {
	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeFile,
		Name:       p.Name,
		BOMRef:     p.BomRef,
		Properties: getPatchProperties(&p),
	}
}

func encodeLicenses(lic []string) *cyclonedx.Licenses {
	out := cyclonedx.Licenses{}
	for _, v := range lic {
		license, err := _package.ParseLicenseExpression(v)
		if err != nil {
			fmt.Println("非法的SPDX license格式，", err)
			continue
		}

		out = append(out, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: license,
			},
		})
	}

	return &out
}

func encodeExternalReferences(url string) *[]cyclonedx.ExternalReference {
	var refs []cyclonedx.ExternalReference
	if url != "" {
		refs = append(refs, cyclonedx.ExternalReference{
			URL:  url,
			Type: cyclonedx.ERTypeWebsite,
		})
	}
	if len(refs) > 0 {
		return &refs
	}
	return nil
}

func getMetadataComponentProperties(m *_package.Metadata) *[]cyclonedx.Property {
	var out []cyclonedx.Property
	if m.Release != "" {
		out = append(out, cyclonedx.Property{
			Name:  "release",
			Value: m.Release,
		})
	}
	if m.IsNative != "" {
		out = append(out, cyclonedx.Property{
			Name:  "isNativePackage",
			Value: m.IsNative,
		})
	}
	if m.Architecture != "" {
		out = append(out, cyclonedx.Property{
			Name:  "architecture",
			Value: m.Architecture,
		})
	}
	if m.SourcePkg != "" {
		out = append(out, cyclonedx.Property{
			Name:  "sourcePkg",
			Value: m.SourcePkg,
		})
	}
	if len(m.Sources) != 0 {
		out = append(out, cyclonedx.Property{
			Name:  "sourceFiles",
			Value: strings.Join(m.Sources, ", "),
		})
	}
	if m.Maintainer != "" {
		out = append(out, cyclonedx.Property{
			Name:  "maintainer",
			Value: m.Maintainer,
		})
	}
	if m.OriginalMaintainer != "" {
		out = append(out, cyclonedx.Property{
			Name:  "originalMaintainer",
			Value: m.OriginalMaintainer,
		})
	}
	if m.Packager != "" {
		out = append(out, cyclonedx.Property{
			Name:  "packager",
			Value: m.Packager,
		})
	}
	if m.BuildTime != "" {
		out = append(out, cyclonedx.Property{
			Name:  "buildTime",
			Value: m.BuildTime,
		})
	}
	if m.BuildHost != "" {
		out = append(out, cyclonedx.Property{
			Name:  "buildHost",
			Value: m.BuildHost,
		})
	}
	if m.PackageList != "" {
		out = append(out, cyclonedx.Property{
			Name:  "packageList",
			Value: m.PackageList,
		})
	}
	if m.Section != "" {
		out = append(out, cyclonedx.Property{
			Name:  "section",
			Value: m.Section,
		})
	}
	if m.Priority != "" {
		out = append(out, cyclonedx.Property{
			Name:  "priority",
			Value: m.Priority,
		})
	}
	return &out
}

func getDependProperties(d *_package.Depend) *[]cyclonedx.Property {
	var out []cyclonedx.Property
	out = append(out, cyclonedx.Property{
		Name:  "componentType",
		Value: "depend",
	})
	if d.DebDependType != "" {
		out = append(out, cyclonedx.Property{
			Name:  "dependType",
			Value: d.DebDependType,
		})
	}
	if d.Release != "" {
		out = append(out, cyclonedx.Property{
			Name:  "release",
			Value: d.Release,
		})
	}
	if d.Architecture != "" {
		out = append(out, cyclonedx.Property{
			Name:  "architecture",
			Value: d.Architecture,
		})
	}
	return &out
}

func getBuildDependProperties(bd *_package.BuildDepend) *[]cyclonedx.Property {
	var out []cyclonedx.Property
	out = append(out, cyclonedx.Property{
		Name:  "componentType",
		Value: "buildDepend",
	})
	if bd.DebBuildDependType != "" {
		out = append(out, cyclonedx.Property{
			Name:  "buildDependType",
			Value: bd.DebBuildDependType,
		})
	}
	if bd.Release != "" {
		out = append(out, cyclonedx.Property{
			Name:  "release",
			Value: bd.Release,
		})
	}
	if bd.Architecture != "" {
		out = append(out, cyclonedx.Property{
			Name:  "architecture",
			Value: bd.Architecture,
		})
	}
	out = append(out, cyclonedx.Property{
		Name:  "affectsBinaryComposition",
		Value: fmt.Sprintf("%t", bd.AffectsBinaryComposition),
	})
	if bd.InferentialDescription != "" {
		out = append(out, cyclonedx.Property{
			Name:  "inferentialDescription",
			Value: bd.InferentialDescription,
		})
	}
	return &out
}

func getPatchProperties(p *_package.Patch) *[]cyclonedx.Property {
	var out []cyclonedx.Property
	out = append(out, cyclonedx.Property{
		Name:  "componentType",
		Value: "patch",
	})
	if p.From != "" {
		out = append(out, cyclonedx.Property{
			Name:  "from",
			Value: p.From,
		})
	}
	if p.Date != "" {
		out = append(out, cyclonedx.Property{
			Name:  "date",
			Value: p.Date,
		})
	}
	if p.Subject != "" {
		out = append(out, cyclonedx.Property{
			Name:  "subject",
			Value: p.Subject,
		})
	}
	return &out
}

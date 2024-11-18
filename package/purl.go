package _package

import (
	"fmt"
	"github.com/package-url/packageurl-go"
	"sort"
)

// 源码包PURL：pkg:rpm/openEuler/bash@5.2.15-9.oe2403?arch=x86_64&distro=openEuler-24.03
// 二进制包PURL：pkg:rpm/openEuler/bash@5.2.15-9.oe2403?arch=x86_64&upstream=bash-5.2.15-9.oe2403.src.rpm&distro=openEuler-24.03

// packageURL returns the PURL for the specific RHEL package (see https://github.com/package-url/purl-spec)
func RpmPackageURL(pkgType, namespace, name, arch, sourcePkg, version, release, distro string) string {
	qualifiers := map[string]string{}

	if arch != "" {
		qualifiers["arch"] = arch
	}

	if sourcePkg != "" {
		qualifiers["upstream"] = sourcePkg
	}

	if distro != "" {
		qualifiers["distro"] = distro
	}
	if release != "" {
		version = fmt.Sprintf("%s-%s", version, release)
	}
	return packageurl.NewPackageURL(
		pkgType,
		namespace,
		name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		version,
		PURLQualifiers(qualifiers),
		"",
	).ToString()
}

func PURLQualifiers(vars map[string]string) (q packageurl.Qualifiers) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := vars[k]
		if val == "" {
			continue
		}
		q = append(q, packageurl.Qualifier{
			Key:   k,
			Value: vars[k],
		})
	}
	return q
}

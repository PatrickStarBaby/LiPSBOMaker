package _package

import (
	"fmt"
	"runtime/debug"
	"slp/package/spdxlicense"

	"github.com/github/go-spdx/v2/spdxexp"
)

type Type string

const (
	Declared  Type = "declared"
	Concluded Type = "concluded"
)

// 返回格式化的标准license名称
func ParseLicenseExpression(expression string) (license string, err error) {
	// https://github.com/anchore/syft/issues/1837
	// The current spdx library can panic when parsing some expressions
	// This is a temporary fix to recover and patch until we can investigate and contribute
	// a fix to the upstream github library
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic while parsing license expression at: \n%s", string(debug.Stack()))
		}
	}()

	licenseID, exists := spdxlicense.ID(expression)
	if exists {
		return licenseID, nil
	}
	// If it doesn't exist initially in the SPDX list it might be a more complex expression
	// ignored variable is any invalid expressions
	// TODO: contribute to spdxexp to expose deprecated license IDs
	// https://github.com/anchore/syft/issues/1814
	valid, _ := spdxexp.ValidateLicenses([]string{expression})
	if !valid {
		//return "", fmt.Errorf("invalid SPDX expression: %s", expression)
		fmt.Println("invalid SPDX expression: ", expression)
	}

	return expression, nil
}

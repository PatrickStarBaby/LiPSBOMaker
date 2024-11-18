package _package

import (
	"fmt"
	"testing"
)

func TestIDByHash(t *testing.T) {
	tests := []struct {
		name string
		obj  interface{}
	}{
		{
			name: "test1",
			obj:  "rpm",
		},
		{
			name: "test2",
			obj:  "rpm",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := IDByHash(test.obj)
			if err != nil {
				fmt.Println("actual:", actual)
			}
		})
	}
}

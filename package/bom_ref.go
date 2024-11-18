package _package

import (
	"fmt"
	"github.com/mitchellh/hashstructure/v2"
	"time"
)

// prefix 可以是 purl 也可以是patch类型
func GetBomRef(prefix string, obj interface{}, identifier string) (string, error) {
	id, err := IDByHash(obj)
	return fmt.Sprintf("%s&%s=%s", prefix, identifier, id), err
}

func IDByHash(obj interface{}) (string, error) {
	newObj := struct {
		Obj       interface{}
		Timestamp time.Time //加上时间戳防止重复
	}{
		Obj:       obj,
		Timestamp: time.Now(),
	}
	f, err := hashstructure.Hash(newObj, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", fmt.Errorf("could not build ID for object=%+v: %w", obj, err)
	}

	return fmt.Sprintf("%016x", f), nil
}

package secureio

import (
	"github.com/mohae/deepcopy"
)

func copyForDebug(in ...interface{}) (result []interface{}) {
	result = make([]interface{}, 0, len(in))
	for _, item := range in {
		result = append(result, copyForDebugItem(item))
	}
	return
}

func copyForDebugItem(item interface{}) interface{} {
	switch item := item.(type) {
	case interface{ duplicate() interface{} }:
		return item.duplicate()
	default:
		return deepcopy.Copy(item)
	}
}

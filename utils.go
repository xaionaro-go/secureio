package secureio

func min(args ...int) (result int) {
	result = args[0]
	for _, arg := range args[1:] {
		if arg < result {
			result = arg
		}
	}
	return
}

func umin(args ...uint) (result uint) {
	result = args[0]
	for _, arg := range args[1:] {
		if arg < result {
			result = arg
		}
	}
	return
}

func u32min(args ...uint32) (result uint32) {
	result = args[0]
	for _, arg := range args[1:] {
		if arg < result {
			result = arg
		}
	}
	return
}

func u64min(args ...uint64) (result uint64) {
	result = args[0]
	for _, arg := range args[1:] {
		if arg < result {
			result = arg
		}
	}
	return
}

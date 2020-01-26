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

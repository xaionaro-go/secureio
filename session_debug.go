// +build secureiodebug testlogging

package secureio

func (sess *Session) ifDebug(fn func()) {
	if !sess.options.EnableDebug {
		return
	}

	fn()
}

func (sess *Session) isDebugEnabled() bool {
	return sess.options.EnableDebug
}

func (sess *Session) debugf(format string, args ...interface{}) {
	sess.ifDebug(func() {
		defer func() { recover() }()
		select {
		case sess.debugOutputChan <- DebugOutputEntry{Format: format, Args: copyForDebug(args...)}:
		default:
		}
	})
}

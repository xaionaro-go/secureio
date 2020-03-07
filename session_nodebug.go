// +build !secureiodebug,!testlogging

package secureio

func (sess *Session) ifDebug(fn func()) {
}
func (sess *Session) isDebugEnabled() bool {
	return false
}
func (sess *Session) debugf(format string, args ...interface{}) {
}

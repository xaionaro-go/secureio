package secureio

type EventHandler interface {
	OnInit(*Session)
	OnConnect(*Session)
	Error(*Session, error)
	Infof(string, ...interface{})
	Debugf(string, ...interface{})
	IsDebugEnabled() bool
}

type dummyEventHandler struct{}

func (h *dummyEventHandler) OnInit(*Session)               {}
func (h *dummyEventHandler) OnConnect(*Session)            {}
func (h *dummyEventHandler) IsDebugEnabled() bool          { return false }
func (h *dummyEventHandler) Error(*Session, error)         {}
func (h *dummyEventHandler) Infof(string, ...interface{})  {}
func (h *dummyEventHandler) Debugf(string, ...interface{}) {}

type errorHandlerWrapper struct {
	EventHandler
	ErrorHandler func(*Session, error)
}

func wrapErrorHandler(
	eventHandler EventHandler,
	errorHandler func(*Session, error),
) EventHandler {
	if eventHandler == nil {
		eventHandler = &dummyEventHandler{}
	}
	return &errorHandlerWrapper{eventHandler, errorHandler}
}

func (wrapper *errorHandlerWrapper) Error(sess *Session, err error) {
	wrapper.ErrorHandler(sess, err)
}

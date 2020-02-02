package secureio

type EventHandler interface {
	OnInit(*Session)
	OnConnect(*Session)
	Error(*Session, error) bool
}

type dummyEventHandler struct{}

func (h *dummyEventHandler) OnInit(*Session)            {}
func (h *dummyEventHandler) OnConnect(*Session)         {}
func (h *dummyEventHandler) IsDebugEnabled() bool       { return false }
func (h *dummyEventHandler) Error(*Session, error) bool { return false }

type errorHandlerWrapper struct {
	EventHandler
	ErrorHandler func(*Session, error) bool
}

func wrapErrorHandler(
	eventHandler EventHandler,
	errorHandler func(*Session, error) bool,
) EventHandler {
	if eventHandler == nil {
		eventHandler = &dummyEventHandler{}
	}
	return &errorHandlerWrapper{eventHandler, errorHandler}
}

func (wrapper *errorHandlerWrapper) Error(sess *Session, err error) bool {
	return wrapper.ErrorHandler(sess, err)
}

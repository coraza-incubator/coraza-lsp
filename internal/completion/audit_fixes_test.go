package completion

import "testing"

// A negative cursor offset (some clients send one for an out-of-range position)
// must not panic.
func TestDetectContext_NegativeOffsetNoPanic(t *testing.T) {
	ctx, prefix := DetectContext("SecRule ARGS", -5)
	_ = ctx
	_ = prefix // just assert it returned without panicking
}

// Inside the operator argument (after `@op `), context is ContextOperatorArg,
// not ContextOperator (which is only for selecting the operator name).
func TestDetectContext_OperatorArgVsName(t *testing.T) {
	// Cursor still on the operator name.
	ctx, _ := DetectContext(`SecRule ARGS "@r`, len(`SecRule ARGS "@r`))
	if ctx != ContextOperator {
		t.Fatalf("typing operator name: got %v, want ContextOperator", ctx)
	}
	// Cursor in the operator argument.
	line := `SecRule ARGS "@rx `
	ctx, _ = DetectContext(line, len(line))
	if ctx != ContextOperatorArg {
		t.Fatalf("inside operator arg: got %v, want ContextOperatorArg", ctx)
	}
}

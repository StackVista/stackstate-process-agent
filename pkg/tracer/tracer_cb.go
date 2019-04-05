package tracer

type Callback interface {
	LostV4(uint64)
	LostV6(uint64)
}

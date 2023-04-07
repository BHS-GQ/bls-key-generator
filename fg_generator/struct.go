package fg_generator

type PriShare struct {
	Index int    `json:"Index"`
	Pri   []byte `json:"Pri"`
}

type PubKeys struct {
	Index int    `json:"Index"`
	Share []byte `json:"Share"`
	Group []byte `json:"Group"`
}

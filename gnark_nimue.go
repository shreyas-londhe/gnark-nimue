package gnark_nimue

import "fmt"

type OpKind uint8

const (
	Absorb OpKind = iota
	Squeeze
	Ratchet
)

type Op struct {
	Kind  OpKind
	Label []byte
	Size  uint64
}

type IOPattern struct {
	DomainSeparator []byte
	Ops             []Op
}

func (io *IOPattern) PPrint() string {
	result := "IOPattern {\n"
	result += fmt.Sprintf("  DomainSeparator: %s\n", io.DomainSeparator)
	result += fmt.Sprintf("  Ops:\n")
	for _, op := range io.Ops {
		kindTag := ""
		switch op.Kind {
		case Absorb:
			kindTag = "Absorb"
		case Squeeze:
			kindTag = "Squeeze"
		case Ratchet:
			kindTag = "Ratchet"
		}
		result += fmt.Sprintf("    * %s %d %s\n", kindTag, op.Size, op.Label)
	}
	result += fmt.Sprintf("}")

	return result
}

const SepByte byte = 0

func parseUntilSep(buf []byte, sep byte) (result []byte, rest []byte) {
	for i, b := range buf {
		if b == sep {
			return buf[:i], buf[i+1:]
		}
	}
	return buf, nil
}

func parseOpKind(patStr []byte) (OpKind, []byte, error) {
	if len(patStr) == 0 {
		return 0, nil, fmt.Errorf("parseOpKind: empty input")
	}
	switch patStr[0] {
	case 'A':
		return Absorb, patStr[1:], nil
	case 'S':
		return Squeeze, patStr[1:], nil
	case 'R':
		return Ratchet, patStr[1:], nil
	}
	return 0, nil, fmt.Errorf("parseOpKind: unknown op kind: %s", string(patStr[:1]))
}

func parseSize(patStr []byte) (uint64, []byte) {
	var result uint64 = 0
	for i, b := range patStr {
		if b < '0' || b > '9' {
			return result, patStr[i:]
		}
		result = result*10 + uint64(b-'0')
	}
	return result, nil
}

func parseOp(patStr []byte) (Op, []byte, error) {
	kind, patStr, err := parseOpKind(patStr)
	if err != nil {
		return Op{}, patStr, err
	}
	size, patStr := parseSize(patStr)
	label, patStr := parseUntilSep(patStr, SepByte)
	return Op{Kind: kind, Label: label, Size: size}, patStr, nil
}

func (io *IOPattern) Parse(patStr []byte) error {
	io.DomainSeparator, patStr = parseUntilSep(patStr, SepByte)
	for len(patStr) > 0 {
		nextOp, nextPatStr, err := parseOp(patStr)
		if err != nil {
			return err
		}
		io.Ops = append(io.Ops, nextOp)
		patStr = nextPatStr
	}
	return nil
}

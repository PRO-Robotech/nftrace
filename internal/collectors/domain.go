package collectors

type (
	NftTrace struct {
		TraceHash  uint32
		Table      string
		Chain      string
		JumpTarget string
		RuleHandle uint64
		Family     byte
		Type       uint32
		Id         uint32
		Iif        uint32
		Oif        uint32
		Mark       uint32
		Verdict    uint32
		Nfproto    uint32
		Policy     uint32
		Iiftype    uint16
		Oiftype    uint16
		Iifname    string
		Oifname    string
		SMacAddr   string
		DMacAddr   string
		IpVersion  uint8
		SAddr      string
		DAddr      string
		SPort      uint32
		DPort      uint32
		Length     uint32
		IpProtocol uint8
		Cnt        uint64
		ReadyMsk   bool
		Metrics    Telemetry
	}

	CollectorMsg struct {
		Trace NftTrace
		Err   error
	}
)

func (n *NftTrace) Reset() {
	*n = NftTrace{}
}

module github.com/PRO-Robotech/nftrace

go 1.24.2

require (
	github.com/H-BF/corlib v1.2.24-dev
	github.com/Morwran/nft-go v0.0.4
	github.com/cespare/xxhash v1.1.0
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/google/nftables v0.3.0
	github.com/jellydator/ttlcache/v3 v3.3.0
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42
	github.com/stretchr/testify v1.10.0
	go.uber.org/zap v1.22.0
)

replace github.com/google/nftables v0.3.0 => github.com/H-BF/nftables v0.3.0-dev

replace github.com/vishvananda/netlink v1.3.0 => github.com/H-BF/netlink v1.3.0-dev

require (
	github.com/ahmetb/go-linq/v3 v3.2.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/shirou/gopsutil/v3 v3.24.5 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
)

replace github.com/H-BF/corlib v1.2.24-dev => github.com/PRO-Robotech/corelib v1.2.24-dev

replace github.com/Morwran/nft-go v0.0.4 => github.com/PRO-Robotech/nft-go v0.0.4-dev

require (
	github.com/cilium/ebpf v0.18.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/vishvananda/netlink v1.3.0
	golang.org/x/sys v0.30.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

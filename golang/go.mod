module main

go 1.22.4

require (
	github.com/google/go-tpm v0.9.3
	github.com/google/go-tpm-tools v0.4.4
	github.com/pion/dtls/v2 v2.2.12
)

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20241207144721-04534a2f2feb // indirect
	github.com/google/go-configfs-tsm v0.3.2 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/pion/dtls/v2 => ./dtls

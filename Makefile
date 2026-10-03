.PHONY: check fmt

check:
	@test -z "$$(gofmt -l workload bundle internal extension)" || { gofmt -l workload bundle internal extension; exit 1; }
	go vet ./...
	go test ./...
	go build ./...

fmt:
	gofmt -w workload bundle internal extension

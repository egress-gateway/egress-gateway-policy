.PHONY: check fmt

check:
	@test -z "$$(gofmt -l workload bundle)" || { gofmt -l workload bundle; exit 1; }
	go vet ./...
	go test ./...
	go build ./...

fmt:
	gofmt -w workload bundle

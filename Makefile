.PHONY: check fmt

check:
	@test -z "$$(gofmt -l workload bundle internal)" || { gofmt -l workload bundle internal; exit 1; }
	go vet ./...
	go test ./...
	go build ./...

fmt:
	gofmt -w workload bundle internal

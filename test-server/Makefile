test-server:
	go build -o test-server ./main.go

.PHONY: format
format:
	go fmt ./...

all: test-server

.PHONY: test
test:
	go test -v -p 1 -race ./...

clean:
	rm -rf test-server

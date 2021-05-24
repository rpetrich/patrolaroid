.PHONY: all
all: crassidens

.PHONY: clean
clean:
	rm -rf crassidens

crassidens:
	CGO_ENABLED=1 go build -o crassidens main.go

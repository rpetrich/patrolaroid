.PHONY: all
all: patrolaroid

.PHONY: clean
clean:
	rm -rf patrolaroid

patrolaroid: main.go
	CGO_ENABLED=1 go build -o patrolaroid main.go

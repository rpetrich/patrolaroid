.PHONY: all
all: patrolaroid

.PHONY: clean
clean:
	rm -rf patrolaroid patrolaroid.tar.gz

patrolaroid: main.go
	CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags -static" -o patrolaroid main.go

patrolaroid.tar.gz: patrolaroid
	tar cfz patrolaroid.tar.gz patrolaroid rules/

.PHONY: package
package: patrolaroid.tar.gz

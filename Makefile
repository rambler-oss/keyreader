release:release_linux
debug:	debug_linux

release_freebsd:
	GOOS=freebsd GOARCH=amd64 go build -ldflags='-s' -o keyreader-freebsd-amd64 .

release_linux:
	GOOS=linux GOARCH=amd64 go build -ldflags='-s' -o keyreader-linux-amd64 .


debug_freebsd:
	GOOS=freebsd GOARCH=amd64 go build -o keyreader-freebsd-amd64 .

debug_linux:
	GOOS=linux GOARCH=amd64 go build -o keyreader-linux-amd64 .


clean:
	rm -f keyreader-freebsd-amd64 keyreader-linux-amd64

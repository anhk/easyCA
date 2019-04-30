export GOPATH=$(shell pwd):$(shell pwd)/vendors

OBJ = easyCA

all: $(OBJ)

$(OBJ):
	cd src && go build -gcflags "-N -l" -o ../$@

clean:
	rm -fr $(OBJ)

-include .deps

dep:
	echo -n "$(OBJ):" > .deps
	find src -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps

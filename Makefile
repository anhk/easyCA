export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = easyCA

default: $(OBJ)

$(OBJ):
	go build -gcflags "-N -l" -o $@ .

clean:
	rm -fr $(OBJ)

-include .deps

dep:
	echo -n "$(OBJ):" > .deps
	find . -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps

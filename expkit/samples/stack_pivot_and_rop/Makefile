TARGET ?= kernelctf lts-6.1.81
SRCS := $(shell find ../.. -name "*.cpp" ! -path "../../samples/*" ! -path "../../test/*")
OBJS := $(SRCS:.cpp=.o)
CC = g++
CFLAGS = -static -I../.. -g

build: exp

clean:
	rm exp

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

exp: exp.o $(OBJS) target_db.kpwn
	$(CC) $(CFLAGS) $(OBJS) exp.o -o exp

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: build
	cp exp* ../../../kernel-image-runner/rootfs/
	../../../kernel-image-runner/run.sh $(TARGET) --custom-modules=kpwn --only-command-output --dmesg=dmesg.txt -- /exp.sh|tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; grep -q ExpKitError output.txt || { echo "dmesg content: "; cat dmesg.txt; }; exit 1; }

stability_test: build
	cp exp* ../../../kernel-image-runner/rootfs/
	../../../kernel-image-runner/test/run_stability_test.sh $(TARGET) /exp.sh

echo:
	echo $(TARGET)

# ADJUST THIS PATH if KernelXDK is installed elsewhere (e.g., /opt/my_libs)
KERNELXDK_INSTALL_PREFIX ?= /usr/local

KERNELXDK_INCLUDE_DIR ?= $(KERNELXDK_INSTALL_PREFIX)/include/
KERNELXDK_LIB_DIR ?= $(KERNELXDK_INSTALL_PREFIX)/lib

TARGET ?= kernelctf lts-6.1.81
CC = g++
CFLAGS = -static -I../.. -I$(KERNELXDK_INCLUDE_DIR) -g
LDFLAGS := -L$(KERNELXDK_LIB_DIR) -lkernelXDK

build: exp

clean:
	rm exp *.o

exp: exploit.o $(OBJS) target_db.kxdb
	$(CC) $(CFLAGS) exploit.o $(LDFLAGS) -o exp

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

target_db.kxdb:
	wget -O target_db.kxdb https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kxdb

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

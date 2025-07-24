# ADJUST THIS PATH if KernelXDK is installed elsewhere (e.g., /opt/my_libs)
KERNELXDK_INSTALL_PREFIX ?= /usr/local

KERNELXDK_INCLUDE_DIR := $(KERNELXDK_INSTALL_PREFIX)/include/
KERNELXDK_LIB_DIR := $(KERNELXDK_INSTALL_PREFIX)/lib

TARGET ?= kernelctf lts-6.1.79
CC = g++
CFLAGS := -I. -I$(KERNELXDK_INCLUDE_DIR) -I/usr/include/libnl3 -static -g
LDFLAGS := -L$(KERNELXDK_LIB_DIR) -lkernelXDK -lnl-nf-3 -lnl-route-3 -lnl-3


exp: exploit.o $(OBJS) target_db.kpwn
	$(CC) $(CFLAGS) exploit.o $(LDFLAGS) -o exp

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

prerequisites:
	sudo apt-get install libnl-nf-3-dev libnl-route-3-dev

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: exp
	cp exp* ../../../kernel-image-runner/rootfs/
	../../../kernel-image-runner/run.sh $(TARGET) -- /exp.sh | tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; echo "dmesg content: "; cat dmesg.txt; exit 1; }

echo:
	echo $(TARGET)

clean:
	rm -f exploit.o exp output.txt dmesg.txt target_db.kpwn
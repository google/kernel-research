TARGET ?= kernelctf lts-6.1.36
#TARGET ?= kernelctf cos-101-17162.210.48
#TARGET ?= kernelctf mitigation-6.1-v2

INCLUDES = -I/usr/include/libnl3 -I../..
LIBS = -pthread -lnl-cli-3 -lnl-route-3 -lnl-3 -ldl

build: exp

exp: target_db.kpwn exploit.cpp
	g++ -o exp exploit.cpp $(INCLUDES) $(LIBS) -static -fomit-frame-pointer 

prerequisites:
	sudo apt-get install libnl-cli-3-dev libnl-route-3-dev

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: build
	cp exp* ../../../kernel-image-runner/rootfs/
	../../../kernel-image-runner/run.sh $(TARGET) --nokaslr -- /exp.sh 0xffffffff81000000 | tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; echo "dmesg content: "; cat dmesg.txt; exit 1; }

echo:
	echo $(TARGET)

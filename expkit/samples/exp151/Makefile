TARGET ?= kernelctf lts-6.1.79
#TARGET ?= kernelctf cos-105-17412.294.34

INCLUDES = -I/usr/include/libnl3 -I../..
LIBS = -lnl-nf-3 -lnl-route-3 -lnl-3

build: exp

exp: target_db.kpwn exploit.cpp
	g++ -o exp exploit.cpp $(INCLUDES) $(LIBS) -static

prerequisites:
	sudo apt-get install libnl-nf-3-dev libnl-route-3-dev

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: build
#run:
	cp exp* ../../../kernel-image-runner/rootfs/
	#../../../kernel-image-runner/run.sh $(TARGET) --gdb --dbgsym --nokaslr -- /exp.sh | tee output.txt
	../../../kernel-image-runner/run.sh $(TARGET) -- /exp.sh | tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; echo "dmesg content: "; cat dmesg.txt; exit 1; }

echo:
	echo $(TARGET)

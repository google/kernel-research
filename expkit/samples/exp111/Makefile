#TARGET ?= kernelctf lts-6.1.61
TARGET ?= kernelctf cos-105-17412.226.28

build: exp

exp: target_db.kpwn exploit.cpp
	g++ -Wno-format -static -I../.. -o exp exploit.cpp

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: build
	cp exp* ../../../kernel-image-runner/rootfs/
	#../../../kernel-image-runner/run.sh $(TARGET) --gdb --dbgsym --nokaslr -- /exp.sh | tee output.txt
	../../../kernel-image-runner/run.sh $(TARGET) --nokaslr -- /exp.sh | tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; echo "dmesg content: "; cat dmesg.txt; exit 1; }

echo:
	echo $(TARGET)

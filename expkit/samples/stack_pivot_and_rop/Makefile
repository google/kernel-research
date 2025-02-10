TARGET ?= kernelctf lts-6.1.81

build: exp

exp: target_db.kpwn exp.cpp
	g++ -static -I../.. -o exp exp.cpp

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

run: build
	cp exp* ../../../kernel-image-runner/rootfs/
	../../../kernel-image-runner/run.sh $(TARGET) --custom-modules=kpwn --only-command-output --dmesg=dmesg.txt -- /exp.sh|tee output.txt

test: run
	grep "CTF{secret_flag_deadbeef}" output.txt || { echo "Failed to leak the flag."; grep -q ExpKitError output.txt || { echo "dmesg content: "; cat dmesg.txt; }; exit 1; }

echo:
	echo $(TARGET)

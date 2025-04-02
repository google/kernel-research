SRCS := $(shell find . -name "*.cpp")

exp: $(SRCS) target_db.kpwn
	g++ -static -I. -o exp exp.cpp

test: bin/test
	bin/test --test-suites StaticTests --tests ^TODO

bin/test: $(SRCS) test/artifacts/target_db_lts-6.1.81.kpwn test/artifacts/kernelctf.kpwn
	mkdir -p bin
	g++ -static -I. -o bin/test test/main.cpp

test/artifacts/kernelctf.kpwn:
	wget -O test/artifacts/kernelctf.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

test/artifacts/target_db_lts-6.1.81.kpwn:
	../kpwn_db/kpwn_db.py --kernel-image-db-path=../kernel-image-db --release-filter-add lts-6.1.81 -o test/artifacts/target_db_lts-6.1.81.kpwn

SRCS := $(shell find . -name "*.cpp" ! -path "./samples/*")
SAMPLES := $(shell ls samples)
OBJS := $(SRCS:.cpp=.o)
CC = g++
CFLAGS = -static -I. -g

exp: $(SRCS) target_db.kpwn
	g++ -static -I. -o exp exp.cpp

test: bin/test
	bin/test --test-suites StaticTests --tests ^TODO

bin/test: $(OBJS) test/artifacts/target_db_lts-6.1.81.kpwn test/artifacts/kernelctf.kpwn
	mkdir -p bin
	$(CC) $(CFLAGS) $(OBJS) -o bin/test

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

test/artifacts/kernelctf.kpwn:
	wget -O test/artifacts/kernelctf.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

test/artifacts/target_db_lts-6.1.81.kpwn:
	../kpwn_db/kpwn_db.py --kernel-image-db-path=../kernel-image-db --release-filter-add lts-6.1.81 -o test/artifacts/target_db_lts-6.1.81.kpwn

clean:
	rm $(OBJS)

$(SAMPLES):
ifdef PREREQ
	if make -C samples/$@ -n prerequisites; then make -C samples/$@ prerequisites; fi
endif
	make -j`nproc` -C samples/$@ build

samples: $(SAMPLES)

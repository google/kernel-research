SRCS := $(shell find . -name "*.cpp")

exp: $(SRCS) target_db.kpwn
	g++ -static -I. -o exp exp.cpp

test: bin/test

bin/test: $(SRCS) test/artifacts/target_db_lts-6.1.81.kpwn
	g++ -static -I. -o bin/test test/main.cpp

test/artifacts/target_db_lts-6.1.81.kpwn:
	../kpwn_db_generator/kpwn_db_generator.py --release-filter lts-6.1.81 --output-path ../expkit/test/artifacts/target_db_lts-6.1.81.kpwn ../../tools/kernel-image-db

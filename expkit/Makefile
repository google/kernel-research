# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SRCS := $(shell find . -name "*.cpp")
SAMPLES := $(shell ls samples)

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

$(SAMPLES):
ifdef PREREQ
	if make -C samples/$@ -n prerequisites; then make -C samples/$@ prerequisites; fi
endif
	make -C samples/$@ build

samples: $(SAMPLES)

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

TARGET ?= kernelctf lts-6.1.81

build: exp

clean:
	rm exp

exp: target_db.kpwn exp.cpp
	g++ -static -I../.. -o exp exp.cpp

target_db.kpwn:
	wget -O target_db.kpwn https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn

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

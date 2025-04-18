#!/bin/sh
# Copyright 2024 Google LLC
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

echo "=== COMMAND-BEGIN: $@ ==="
eval $@ > /output 2>/output
echo "=== COMMAND-END ==="

# make sure this is written out fully and not to be mixed with dmesg messages
# TODO: make this better, e.g. separate the streams altogether
sleep 0.1
#!/bin/bash
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

set -e

process_distro() {
    DISTRO_NAME="$1"
    DISTRO_ID="${DISTRO_NAME,,}"

    yq -r ".$DISTRO_ID|keys[]" releases.yaml | while read -r RELEASE; do
        echo "====================================================="
        echo "Processing $DISTRO_NAME release: $RELEASE"
        echo "====================================================="
        ./download_release.sh $DISTRO_ID $RELEASE
    done
}

process_distro kernelCTF
process_distro Ubuntu

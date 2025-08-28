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
set -eo pipefail

if [ "$1" == "--rebuild" ]; then
    echo -n > gcs_releases.txt
else
    gcloud storage ls gs://kernel-research/pwnkit/db/kernelctf/*.kxdb |sed -E "s/.*kernelctf\/(.*)\.kxdb/\\1/" > gcs_releases.txt
fi

# gcloud storage ls gs://kernelctf-build/releases | sed "s/.*releases\/\(.*\)\//\1/" > build_releases.txt

# missing_releases = kernelctf_releases without gcs_releases and skipped_releases
curl -s https://raw.githubusercontent.com/google/security-research/master/kernelctf/server/releases.yaml | grep -Eoh "^[^: ]*"  > kernelctf_releases.txt
cat kernelctf_releases.txt | grep -v -f gcs_releases.txt | grep -v -f <(cat skipped_releases.txt | sed 's/\s*#.*//') > missing_gcs_releases.txt || true

if [[ ! -s "missing_gcs_releases.txt" ]]; then echo "Nothing is missing from GCS, exiting..."; exit 0; fi

echo "The following releases were not processed yet: "
cat missing_gcs_releases.txt | sed 's/$/, /' | tr -d '\n'
echo

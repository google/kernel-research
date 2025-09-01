/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const fs = require('fs');

async function main() {
    const url = `https://github.com/google/kernel-research/actions/runs/${process.env.GITHUB_RUN_ID}`;
    const pp = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, {encoding: 'utf8'}));

    let text = `*GHA FAIL*: workflow <${url}|${process.env.GITHUB_WORKFLOW}> by ${process.env.GITHUB_ACTOR} failed`;
    if (pp.pull_request)
      text += ` for PR #${pp.pull_request.number} ("${pp.pull_request.title}")`;
    else if (pp.head_commit)
      text += ` for commit ${pp.head_commit.id.substr(0,7)} ("${pp.head_commit.message}")`;

    fetch(process.env.WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "text": text })
    });
}

main();

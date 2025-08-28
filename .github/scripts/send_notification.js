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

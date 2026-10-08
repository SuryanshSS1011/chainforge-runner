# chainforge-runner

Clean-host replay of public [ARVO](https://github.com/n132/ARVO) reproduction images
(`n132/arvo:<id>-vul` / `-fix`) on GitHub-hosted runners, for the CHAINFORGE dataset's
independent re-run and for cases that need a privileged Docker host.

This repository holds **only** the replay script and lists of ARVO case ids. It contains no
dataset records, labels or logs; results are uploaded as workflow artifacts.

- `scripts/rerun.sh <id> <outdir>` — vulnerable image once, patched image twice; a patched run
  counts as clean only if the fuzzing engine reports the input executed.
- `.github/workflows/rerun.yml` — manual dispatch with a case list, sharded across runners.

Run: `gh workflow run rerun -f cases=cases/<list>.txt -f shards=20`

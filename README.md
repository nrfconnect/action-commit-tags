# action-commit-tags
GitHub action to handle commit (sauce) tags checking in Pull Requests

## `[nrf fromtree]` commits

A `[nrf fromtree]` commit must have been cherry-picked with
`git cherry-pick -x`. The action checks that the commit referenced by the
`(cherry picked from commit <SHA>)` line is reachable from one of the
following upstream branches, and that replaying it on top of the PR's merge
base yields exactly the same changes:

- `main`
- `v*-branch` (the upstream release branches)

Only these branch heads are fetched. Commits that exist only in other
branches, pull requests or forks of the upstream repository are rejected.

When a commit was cherry-picked more than once, for instance a backport to
an upstream release branch that is then picked into an NCS fork, it carries
several `cherry picked from` lines. The action considers all of them, skips
those that are not reachable from the branches above (such as SHAs of
downstream commits), and replays the last remaining one. This makes it
possible to take a commit from the upstream release branch, where it may
differ from the one in `main` because of resolved conflicts.

## Inputs

- `upstream`: the upstream `<org>/<repo>`. A trailing `/<branch>` is accepted
  for compatibility but ignored.

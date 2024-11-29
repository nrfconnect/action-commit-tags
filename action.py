#!/usr/bin/env python3
# Copyright (c) 2020, 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0

# standard library imports only here
from typing import Dict, List
from pathlib import Path
import argparse
import functools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from github import Github, GithubException

# 3rd party imports go here, if any are added.

# Portability:
#
# - Python 3.6 or later on POSIX
# - Python 3.7 or later on Windows (some os.PathLike features didn't
#   make it into 3.6 for Windows)

PROG = 'commit-tags'

PARSER = argparse.ArgumentParser(
    prog=PROG,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=f'''\
Runs the gitlint commit (sauce) tag checks in the provided path.
''')
PARSER.add_argument('-t', '--target', type=Path, required=True,
                    help='Target local repo path to run the check on')
PARSER.add_argument('-b', '--baserev', default=None, required=True,
                    help='Base revision to use, all the way to HEAD')
PARSER.add_argument('--pr', default=None, required=True,
                    help='<org>/<repo>/<pr num>')
PARSER.add_argument('--upstream', default=None, required=True,
                    help='Upstream <org>/<repo>')
PARSER.add_argument('--quiet-subprocesses', action='store_true',
                    help='silence output related to running subprocesses')

ARGS = None                     # global arguments, see parse_args()

def stdout(msg):
    print(f'{PROG}: {msg}', file=sys.stdout)
    sys.stdout.flush()

die_switch = None

def die(s):
    print(f'ERROR: {s}', file=sys.stderr)
    print(f'\nMore information about the process can ben found in: '
          f'\nOverall guide to PRs:'
          f'\nhttps://nordicsemi.atlassian.net/wiki/spaces/NCS/pages/108201225/Pull+Requests'
          f'\nCherry-picking commits:'
          f'\nhttps://nordicsemi.atlassian.net/wiki/spaces/NCS/pages/108201225/Pull+Requests#Pull-Requests-to-OSS-repository-forks'
          f'\nCommit (or sauce) tags:'
          f'\nhttps://nordicsemi.atlassian.net/wiki/spaces/NCS/pages/108201225/Pull+Requests#Commit-(or-sauce)-tags'
          f'\n')
    if die_switch:
        # Switch back
        stdout('die: switch')
        try_switch_back(die_switch)
    sys.exit(1)

def gh_pr_split(s):
    sl = s.split('/')
    if len(sl) != 3:
        raise RuntimeError(f"Invalid pr format: {s}")

    return sl[0], sl[1], sl[2]

def parse_args():
    # Parse arguments into the ARGS global, validating them before
    # returning.

    global ARGS

    ARGS = PARSER.parse_args()
    
    stdout(f'target: {ARGS.target} baserev: {ARGS.baserev}')
    stdout(f'pr: {ARGS.pr} upstream: {ARGS.upstream}')

    if ARGS.target == 'none':
        die('--target is required')

    if ARGS.upstream == 'none':
        die('--upstream is required')

    if ARGS.baserev == 'none' and ARGS.pr == 'none':
            die('--baserev or --pr is required')

    if ARGS.baserev != 'none' and ARGS.pr != 'none':
            die('--baserev and --pr are mutually exclusive')

def ssplit(cmd):
    if isinstance(cmd, str):
        return shlex.split(cmd)

    return cmd

def runc(cmd, exit_on_cpe=True, **kwargs):
    # A shorthand for running a simple shell command.

    cwd = os.fspath(kwargs.get('cwd', os.getcwd()))

    if ARGS.quiet_subprocesses:
        kwargs['stdout'] = subprocess.DEVNULL
        kwargs['stderr'] = subprocess.DEVNULL
    else:
        stdout(f'running "{cmd}" in "{cwd}"')

    kwargs['check'] = True
    try:
        ret = subprocess.run(ssplit(cmd), **kwargs)
    except subprocess.CalledProcessError as e:
        if exit_on_cpe:
            die(f'Execution of {cmd} failed with {e.returncode}')
        else:
            raise

    return ret

def runc_out(cmd, exit_on_cpe=True, suppress_stderr=False, **kwargs):
    # A shorthand for running a simple shell command and getting its output.

    cwd = kwargs.get('cwd', os.getcwd())

    if ARGS.quiet_subprocesses or suppress_stderr:
        kwargs['stderr'] = subprocess.DEVNULL
    if not ARGS.quiet_subprocesses:
        stdout(f'running "{cmd}" in "{cwd}"')

    kwargs['check'] = True
    kwargs['universal_newlines'] = True
    kwargs['stdout'] = subprocess.PIPE

    try:
        cp = subprocess.run(ssplit(cmd), **kwargs)
    except subprocess.CalledProcessError as e:
        if exit_on_cpe:
            die(f'Execution of {cmd} failed with {e.returncode}')
        else:
            raise

    return cp.stdout.rstrip()

@functools.cache
def fetch_branch(repo, branch, target):
    ref = f'nrf/ref/{branch}'
    runc(f'git -C {target} fetch {repo.clone_url} {branch}:{ref}')
    return ref

@functools.cache
def fetch_pr(repo, prn, target):
    pr = repo.get_pull(prn)
    if pr.is_merged():
        die(f'PR #{prn} is merged, please use [nrf fromtree] instead')
    if pr.state == 'closed':
        die(f'PR #{prn} is closed and not merged, please open a new PR')

    revs = dict()
    for rev in pr.get_reviews():
        revs[rev.user.login] = rev.state
    for k,v in revs.items():
        if "CHANGES_REQUESTED" in v:
            die(f'PR #{prn} has requested changes, please resolve those')

    shas = [c.sha for c in pr.get_commits()]
    ref = f'nrf/pull/{prn}'
    runc(f'git -C {target} fetch {repo.clone_url} pull/{prn}/head:{ref}')

    stdout(f'PR #{prn} ref: {ref}')
    stdout(f'PR #{prn} shas: {shas}')
    return ref, shas

def merge_base(target, base, head):
    mb = runc_out(f'git -C {target} merge-base {base} {head}')
    stdout(f'merge base {mb}')
    return mb

@functools.cache
def get_commit_msg(target, sha):
    cm = runc_out(f'git -C {target} show -s --format=%B {sha}').split('\n')
    title = cm[0].lstrip().rstrip()
    body = '\n'.join(cm[1:])

    return title, body

def range_diff(target, s1, s2, stat=False):
    # Compare commit ranges (sha^! is a range for sha itself)
    stats = ' --stat' if stat else ''
    out = runc_out(f'git -C {target} range-diff --no-color{stats} {s1}^! {s2}^!')
    return out

def get_commit_diff(target, sha):
    # Get the diff of a commit (sha^! is a range for sha itself)
    diff = runc_out(f'git -C {target} diff {sha}^!').split('\n')

    return diff

def try_switch_back(target):
    try:
        _ = runc_out(f'git -C {target} switch -', exit_on_cpe=False,
                     suppress_stderr=True)
    except subprocess.CalledProcessError as e:
        pass

def check_commit(urepo, ubranch, target, sha, merge):
    stdout(f'--- Checking commit {sha}')
    title, body = get_commit_msg(target, sha)
    m = re.match(r'^(Revert\s+\")?\[nrf (mergeup|fromtree|fromlist|noup)\]\s+',
                 title)
    if not m:
        die(f'{sha}: Title does not contain a sauce tag '
            f'([nrf mergeup], [nrf fromtree], [nrf fromlist], [nrf noup])')
    revert = m.group(1)
    tag = m.group(2)
    if not tag:
        die(f'{sha}: Title does not contain a sauce tag '
            f'([nrf mergeup], [nrf fromtree], [nrf fromlist], [nrf noup])')
    
    if revert:
        if tag == 'mergeup':
            die('Mergeup commits cannot be reverted')
        regex = r'^This reverts commit \b([a-f0-9]{40})\b\.'
        match = re.search(regex, body, re.MULTILINE)
        if not match:
            die(f'{sha}: revert commit message missing reverted SHA')
        stdout(f'revert: {match.group(1)}')
        # The SHA to replay is the revert commmit's
        usha = sha
    elif tag == 'mergeup':
        # Count the merges in this commit range (sha^! is a range for sha
        # itself)
        count = runc_out(f'git -C {target} rev-list --merges --count {sha}^!')
        if count != '1':
            die('mergeup used in a non-merge commit')
        if not re.match(r'^\[nrf mergeup\] Merge upstream up to commit \b([a-f0-9]{40})\b',
                         title):
            die(f'{sha}: Invalid mergeup commit title')

        # We cannot replay the mergeup commit
        return True
    elif tag == 'fromlist':
        regex = r'^Upstream PR #:\s+(\d+)\s*$'

        match = re.search(regex, body, re.MULTILINE)
        if not match:
            die(f'{sha}: fromlist commit missing an "Upstream PR #:" reference')
        
        upr = match.group(1)
        stdout(f'fromlist: {upr}')

        # Check and Fetch the upstream Pull Request
        ref, shas = fetch_pr(urepo, int(upr), target)

        # Match a commit
        usha = None
        for s in shas:
            t, b = get_commit_msg(target, s)
            # Match the upstream commit title with the downstream one
            if t in title:
                stdout(f'fromlist: Matched upstream PR commit {s}')
                usha = s
                break

        if not usha:
                die(f'{sha}: unable to match any commit from upstream PR #{upr}')

    elif tag == 'fromtree':
        regex = r'^\(cherry picked from commit \b([a-f0-9]{40})\b\)'
        match = re.search(regex, body, re.MULTILINE)
        if not match:
            die(f'{sha}: fromtree commit missing cherry-pick reference. '
                f'Please use "git cherry-pick -x" when cherry-picking')
        #stdout(f'fromtree: {match.group(0)}')

        usha = match.group(1)
        stdout(f'fromtree: {usha}')

        # Fetch the upstream main branch
        ref = fetch_branch(urepo, ubranch, target)

        # Verify that the commit exists at all in the working tree
        _ = runc_out(f'git -C {target} rev-parse --verify {usha}^{{commit}}')

        # Verify that the commit is in the required branch
        contains = runc_out(f'git -C {target} branch {ref} --contains {usha}')

        if not re.match(rf'^.*{ref}.*$', contains):
            die(f'fromtree: upstream branch {ref} does not contain commit {usha}. '
                f'Please check that the commit is merged upstream')

    elif tag == 'noup':
        stdout('noup')
        # The SHA to replay is the noup commmit's
        usha = sha

    # Skip cherry-picking if a merge has been found
    if merge:
        stdout(f'merge: skipping cherry-pick of {sha}')
        return True

    # Cherry-pick the commit into the replay branch
    try:
        out = runc_out(f'git -C {target} cherry-pick {usha}', exit_on_cpe=False)
    except subprocess.CalledProcessError as e:
        # Make sure we abort the cherry-pick
        try:
            _ = runc_out(f'git -C {target} cherry-pick --abort',
                           exit_on_cpe=False)
        except subprocess.CalledProcessError as e:
            pass
        # Ignore it and exit forcefully
        die(f'Unable to cherry-pick commit {usha}. This means that the upstream '
            f'commit does not apply cleanly into the NCS fork. This can happen '
            f'if you modified an upstream commit in order to resolve conflicts, '
            f'but this is not allowed. Instead, revert any [nrf noup] commits that '
            f'may be causing the conflict and cherry-pick any additional prior '
            f'commits from upstream that may be needed in order to avoid a merge '
            f'conflict. Then you can re-apply the reverted [nrf noup] commits.')

    # Execute a diff between the replay branch and the sha to make sure the
    # commit has not been modified
    diff = runc_out(f'git -C {target} diff {sha}')

    if diff:
        die(f'SHA {sha} non-empty diff between fork and upstream. This likely '
            f'means that you modified an upstream commit when cherry-picking. '
            f'This is not allowed. Full diff:\n{diff}')

    return False

def main():
    global die_switch

    parse_args()

    token = os.environ.get('GITHUB_TOKEN', None)
    stdout(f'token: \"{token}\"')

    gh = Github(token or None)

    dcommits = []
    dshas = []

    target = Path(ARGS.target).absolute()
    if not target.is_dir():
        die(f'target repo {target} does not exist; check path')

    org_str, repo_str, br_str = gh_pr_split(ARGS.upstream)
    urepo = gh.get_repo(f'{org_str}/{repo_str}')

    if ARGS.pr != 'none':
        org_str, repo_str, pr_str = gh_pr_split(ARGS.pr)
        drepo = gh.get_repo(f'{org_str}/{repo_str}')
        prn = int(pr_str)
        dpr = drepo.get_pull(prn)
        baserev = merge_base(target, dpr.base.sha, dpr.head.sha)
        headrev = dpr.head.sha
        dcommits = [c for c in dpr.get_commits()]
        dshas = [c.sha for c in dcommits]
        stdout(f'{len(dshas)} commits found in PR')
    else:
        baserev = ARGS.baserev
        headrev = 'HEAD'
        prn = 0

    stdout(f'baserev: {baserev}')
    stdout(f'headrev: {headrev}')
    revs = runc_out(f'git -C {target} rev-list --first-parent {baserev}..{headrev}')
    revs = revs.split('\n')
    revs.reverse()
    stdout(f'{len(revs)} commits found with rev-list')

    # Prepare a replay branch
    replay = f'nrf/replay/{prn}'
    # Create the replay branch
    runc(f'git -C {target} branch -f {replay} {baserev}')
    # Switch to it
    runc(f'git -C {target} switch {replay}')
    die_switch = target

    merge = False
    count = 0
    for r in revs:
        merge = check_commit(urepo, br_str, target, r, merge)
        count += 1
        stdout(f'- Processed commit {count}')

    # Switch back to the previous branch
    stdout('main: switch')
    die_switch = None
    try_switch_back(target)

    if not merge and (dshas and dshas != revs):
        die(f'{dshas} is different from {revs}')

if __name__ == '__main__':
    main()

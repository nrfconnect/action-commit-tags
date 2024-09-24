#!/usr/bin/env python3
# Copyright (c) 2020, 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0

# standard library imports only here
from typing import Dict, List
from pathlib import Path
import argparse
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

def stdout(*msg):
    # Print a diagnostic message to standard error.

    print(f'{PROG}:', *msg)
    sys.stdout.flush()

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
        sys.exit('--target is required')

    if ARGS.upstream == 'none':
        sys.exit('--upstream is required')

    if ARGS.baserev == 'none' and ARGS.pr == 'none':
            sys.exit('--baserev or --pr is required')

    if ARGS.baserev != 'none' and ARGS.pr != 'none':
            sys.exit('--baserev and --pr are mutually exclusive')

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
            sys.exit(f'Execution of {cmd} failed with {e.returncode}')
        else:
            raise

    return ret

def runc_out(cmd, exit_on_cpe=True, **kwargs):
    # A shorthand for running a simple shell command and getting its output.

    cwd = kwargs.get('cwd', os.getcwd())

    if ARGS.quiet_subprocesses:
        kwargs['stderr'] = subprocess.DEVNULL
    else:
        stdout(f'running "{cmd}" in "{cwd}"')

    kwargs['check'] = True
    kwargs['universal_newlines'] = True
    kwargs['stdout'] = subprocess.PIPE

    try:
        cp = subprocess.run(ssplit(cmd), **kwargs)
    except subprocess.CalledProcessError as e:
        if exit_on_cpe:
            sys.exit(f'Execution of {cmd} failed with {e.returncode}')
        else:
            raise

    return cp.stdout.rstrip()

def fetch_upstream(gh, upstream):
    pass

def fetch_pr(gh, pr):
    pass

def merge_base(target, base, head):
    mb = runc_out(f'git -C {target} merge-base {base} {head}')
    stdout(f'merge base {mb}')
    return mb

def check_commit(urepo, target, sha):
    stdout(f'Checking commit {sha}')
    cm = runc_out(f'git -C {target} show -s --format=%B {sha}').split('\n')
    title = cm[0]
    body = '\n'.join(cm[1:])
#    stdout(f'{title}')
#    stdout(f'{body}')
    m = re.match(r'^(Revert\s+\")?\[nrf (mergeup|fromtree|fromlist|noup)\]\s+',
                 title)
    if not m:
        sys_exit(f'{sha}: Title does not contain a sauce tag')
    revert = m.group(1)
    tag = m.group(2)
    if not tag:
        sys_exit(f'{sha}: Title does not contain a sauce tag')
    
    #stdout(tag)

    # Skip the rest of checks if the commit is a revert
    if revert:
        if tag == 'mergeup':
            sys.exit('Mergeup cannot be reverted')
        stdout(f'Revert commit, skipping additional checks')
        return

    if tag == 'mergeup':
        # Count the merges in this commit range (sha^! is a range for sha
        # itself)
        count = runc_out('git rev-list --merges --count {sha}^!')
        if count != '1':
            sys.exit('mergeup used in a non-merge commit')
        if not re.match(r'^\[nrf mergeup\] Merge upstream up to commit \b([a-f0-9]{40})\b',
                         title):
            sys.exit('{sha}: Invalid mergeup commit title')
    elif tag == 'fromlist':
        regex = r'^Upstream PR: (' \
                r'https://github\.com/.*/pull/(\d+)|' \
                r'http://lists.infradead.org/pipermail/hostap/.*\.html' \
                r')'

        match = re.search(regex, body, re.MULTILINE)
        if not match:
            sys_exit(f'{sha}: fromlist commit missing an Upstream PR reference')
        
        #stdout(f'fromlist: {match.group(1)}')
        if urepo:
            upr = match.group(2)
            stdout(f'fromlist: {upr}')
    elif tag == 'fromtree':
        regex = r'^\(cherry picked from commit \b([a-f0-9]{40})\b\)'
        match = re.search(regex, body, re.MULTILINE)
        if not match:
            sys_exit(f'{sha}: fromtree commit missing cherry-pick reference')
        #stdout(f'fromtree: {match.group(0)}')
        if urepo:
            usha = match.group(1)
            stdout(f'fromtree: {usha}')

def main():
    parse_args()

    token = os.environ.get('GITHUB_TOKEN', None)
    stdout(f'token: \"{token}\"')

    gh = Github(token or None)

    dcommits = []
    dshas = []

    target = Path(ARGS.target).absolute()
    if not target.is_dir():
        sys.exit(f'target repo {target} does not exist; check path')

    org_str, repo_str, br_str = gh_pr_split(ARGS.upstream)
    urepo = gh.get_repo(f'{org_str}/{repo_str}')

    if ARGS.pr != 'none':
        org_str, repo_str, pr_str = gh_pr_split(ARGS.pr)
        drepo = gh.get_repo(f'{org_str}/{repo_str}')
        dpr = drepo.get_pull(int(pr_str))
        baserev = merge_base(target, dpr.base.sha, dpr.head.sha)
        headrev = dpr.head.sha
        dcommits = [c for c in dpr.get_commits()]
        dshas = [c.sha for c in dcommits]
        stdout(f'SHAs found in PR: {dshas}')
    else:
        baserev = ARGS.baserev
        headrev = 'HEAD'

    stdout(f'baserev: {baserev}')
    stdout(f'headrev: {headrev}')
    revs = runc_out(f'git -C {target} rev-list --first-parent {baserev}..{headrev}')
    revs = revs.split('\n')
    revs.reverse()
    stdout(f'revs: {revs}')

    rev_str = f"{','.join(revs)},"

    for r in revs:
        check_commit(urepo, target, r)

    if dshas and dshas != revs:
        sys.exit(f'{dshas} is different from {revs}')

if __name__ == '__main__':
    main()

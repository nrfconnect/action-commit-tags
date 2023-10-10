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
import shlex
import shutil
import subprocess
import sys
import tempfile

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
PARSER.add_argument('-r', '--revrange', default=None, required=True,
                    help='Revision range to use in gitlint format')
PARSER.add_argument('--quiet-subprocesses', action='store_true',
                    help='silence output related to running subprocesses')

ARGS = None                     # global arguments, see parse_args()

def stdout(*msg):
    # Print a diagnostic message to standard error.

    print(f'{PROG}:', *msg)
    sys.stdout.flush()

def parse_args():
    # Parse arguments into the ARGS global, validating them before
    # returning.

    global ARGS

    ARGS = PARSER.parse_args()
    
    stdout(f'target: {ARGS.target} baserev: {ARGS.baserev} revrange: {ARGS.revrange}')

    if ARGS.baserev == 'none' and ARGS.revrange == 'none':
        sys.exit('Must specify either baserev or revrange')
    elif ARGS.baserev != 'none' and ARGS.revrange != 'none':
        sys.exit('Must specify only one of baserev or revrange')

def ssplit(cmd):
    if isinstance(cmd, str):
        return shlex.split(cmd)

    return cmd

def runc(cmd, **kwargs):
    # A shorthand for running a simple shell command.

    cwd = os.fspath(kwargs.get('cwd', os.getcwd()))

    if ARGS.quiet_subprocesses:
        kwargs['stdout'] = subprocess.DEVNULL
        kwargs['stderr'] = subprocess.DEVNULL
    else:
        stdout(f'running "{cmd}" in "{cwd}"')

    kwargs['check'] = True
    return subprocess.run(ssplit(cmd), **kwargs)

def runc_out(cmd, **kwargs):
    # A shorthand for running a simple shell command and getting its output.

    cwd = kwargs.get('cwd', os.getcwd())

    if ARGS.quiet_subprocesses:
        kwargs['stderr'] = subprocess.DEVNULL
    else:
        stdout(f'running "{cmd}" in "{cwd}"')

    kwargs['check'] = True
    kwargs['universal_newlines'] = True
    kwargs['stdout'] = subprocess.PIPE
    cp = subprocess.run(ssplit(cmd), **kwargs)
    return cp.stdout

def main():
    parse_args()

    target = Path(ARGS.target).absolute()

    if not target.is_dir():
        sys.exit(f'target repo {target} does not exist; check path')

    if ARGS.revrange == 'none':
        try:
            revs = runc_out(f'git -C {target} rev-list --first-parent {ARGS.baserev}..HEAD')
            revs = revs.replace('\n', ',')
        except subprocess.CalledProcessError:
            sys.exit('git execution exited with error')
    else:
        revs = ARGS.revrange

    stdout(f'Running {PROG} checks on target {target} for range {revs}')
    try:
        runc(f'gitlint --target {target} -c ncs-sauce-tags.enable=true ' \
             f'--commits {revs}', cwd=os.path.dirname(__file__))
    except subprocess.CalledProcessError:
        sys.exit('gitlint execution exited with error')

if __name__ == '__main__':
    main()

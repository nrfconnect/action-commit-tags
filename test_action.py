# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0

# Run with: python3 -m pytest test_action.py

from argparse import Namespace
from types import SimpleNamespace
import os
import subprocess

import pytest

import action

DEADBEEF = 'deadbeef' * 5


class FakeRepo:
    # Hashable stand-in for a github.Repository.Repository
    def __init__(self, clone_url):
        self.clone_url = clone_url


def git(cwd, *args):
    out = subprocess.run(['git', '-C', str(cwd), *args], check=True,
                         capture_output=True, text=True)
    return out.stdout.strip()


def write_commit(cwd, name, text, msg):
    with open(os.path.join(cwd, name), 'a') as f:
        f.write(text)
    git(cwd, 'add', name)
    git(cwd, 'commit', '-q', '-m', msg)
    return git(cwd, 'rev-parse', 'HEAD')


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', os.devnull)
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    for k, v in (('NAME', 'T'), ('EMAIL', 't@example.com')):
        monkeypatch.setenv(f'GIT_AUTHOR_{k}', v)
        monkeypatch.setenv(f'GIT_COMMITTER_{k}', v)
    monkeypatch.setattr(action, 'ARGS', Namespace(quiet_subprocesses=True))
    action.fetch_branches.cache_clear()
    action.get_commit_msg.cache_clear()


@pytest.fixture
def world(tmp_path):
    # An "upstream" with main, a v4.4-branch backport of a main commit and a
    # topic branch that is not allowed, and a fork that has cloned it all
    up = tmp_path / 'upstream'
    up.mkdir()
    git(up, 'init', '-q', '-b', 'main')
    base = write_commit(up, 'f', 'base\n', 'base')
    main = write_commit(up, 'f', 'fix\n', 'fix')
    git(up, 'switch', '-q', '-c', 'v4.4-branch', base)
    git(up, 'cherry-pick', '-x', main)
    backport = git(up, 'rev-parse', 'HEAD')
    git(up, 'switch', '-q', '-c', 'topic', base)
    topic = write_commit(up, 'g', 'topic\n', 'topic')
    git(up, 'switch', '-q', 'main')

    fork = tmp_path / 'fork'
    subprocess.run(['git', 'clone', '-q', str(up), str(fork)], check=True)
    git(fork, 'switch', '-q', '-c', 'downstream', base)
    downstream = write_commit(fork, 'h', 'ds\n', 'downstream')

    return SimpleNamespace(
        urepo=FakeRepo(str(up)), fork=fork, base=base,
        main=main, backport=backport, topic=topic, downstream=downstream)


def test_upstream_split():
    assert action.gh_upstream_split('org/repo') == ('org', 'repo')
    assert action.gh_upstream_split('org/repo/main') == ('org', 'repo')
    for bad in ('org', 'a/b/c/d'):
        with pytest.raises(RuntimeError):
            action.gh_upstream_split(bad)


def test_fetch_branches_only_fetches_allowed_heads(monkeypatch):
    cmds = []
    monkeypatch.setattr(action, 'runc', lambda cmd, **kw: cmds.append(cmd))
    action.fetch_branches(FakeRepo('url'), '/t')

    refspecs = cmds[0][cmds[0].index('url') + 1:]
    assert refspecs == [f'+refs/heads/{b}:refs/heads/nrf/ref/{b}'
                        for b in action.UPSTREAM_BRANCHES]
    assert not any('pull' in r for r in refspecs)


@pytest.mark.parametrize('refs, expected', [
    (['main', 'backport'], 'backport'),     # backport comes last
    (['backport', 'main'], 'main'),         # the last one wins
    (['backport', 'downstream'], 'backport'),  # downstream SHA is ignored
    (['main', 'topic'], 'main'),            # not in an allowed branch
    (['topic'], None),
    (['downstream'], None),
    ([DEADBEEF], None),                     # nonexistent
    ([DEADBEEF, 'main'], 'main'),
    ([], None),
])
def test_select_upstream_sha(world, refs, expected):
    action.fetch_branches(world.urepo, world.fork)
    shas = [DEADBEEF if r == DEADBEEF else getattr(world, r) for r in refs]
    usha = action.select_upstream_sha(world.fork, shas)
    assert usha == (getattr(world, expected) if expected else None)


def pr_commit(w, pick, trailers, tamper=False):
    # Create a [nrf fromtree] commit on top of base, the way it would be in a
    # PR, and leave the replay branch at base
    git(w.fork, 'switch', '-q', '-C', 'pr', w.base)
    git(w.fork, 'cherry-pick', pick)
    title = git(w.fork, 'log', '-1', '--format=%s')
    msg = f'[nrf fromtree] {title}\n\n'
    msg += ''.join(f'(cherry picked from commit {t})\n' for t in trailers)
    if tamper:
        with open(os.path.join(w.fork, 'f'), 'a') as f:
            f.write('tampered\n')
        git(w.fork, 'add', 'f')
    subprocess.run(['git', '-C', str(w.fork), 'commit', '-q', '--amend',
                    '-F', '-'], input=msg, text=True, check=True)
    sha = git(w.fork, 'rev-parse', 'HEAD')
    git(w.fork, 'switch', '-q', '-C', 'replay', w.base)
    return sha


def run_check(w, sha, capsys):
    with pytest.raises(SystemExit) as e:
        action.check_commit(w.urepo, w.fork, sha, False)
    return e.value.code, capsys.readouterr().out


def test_check_commit_clean_pick(world, capsys):
    w = world
    sha = pr_commit(w, w.backport, [w.main, w.backport])
    assert action.check_commit(w.urepo, w.fork, sha, False) is False
    assert f'{w.backport} found in upstream: v4.4-branch' in capsys.readouterr().out


def test_check_commit_tampered(world, capsys):
    w = world
    sha = pr_commit(w, w.backport, [w.main, w.backport], tamper=True)
    code, out = run_check(w, sha, capsys)
    assert code == 1 and 'non-empty diff' in out


def test_check_commit_missing_x(world, capsys):
    w = world
    sha = pr_commit(w, w.backport, [])
    code, out = run_check(w, sha, capsys)
    assert code == 1 and 'missing cherry-pick reference' in out


@pytest.mark.parametrize('ref', ['topic', 'downstream', DEADBEEF])
def test_check_commit_not_upstream(world, capsys, ref):
    w = world
    sha = pr_commit(w, w.backport, [DEADBEEF if ref == DEADBEEF
                                    else getattr(w, ref)])
    code, out = run_check(w, sha, capsys)
    assert code == 1 and 'is contained in an upstream branch' in out

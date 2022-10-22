#!/usr/bin/env python
# -*- coding: utf-8; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-

# autopatch.py: script to manage patches on top of repo
# Copyright (c) 2015, Intel Corporation.
# Author: Falempe Jocelyn <jocelyn.falempe@intel.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

from __future__ import print_function

import subprocess
import os
import sys
import json
import tarfile
import threading
import ConfigParser
from optparse import OptionParser


class CommandError(Exception):
    """
    Dummy error, to handle failed git command nicely
    """
    pass


def print_verbose(a):
    if verbose:
        print(a)


def call(wd, cmd, quiet=False, raise_error=True):
    """
    call an external program in a specific directory
    """
    print_verbose('{0}: {1}'.format(wd, ' '.join(cmd)))

    P = subprocess.Popen(args=cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=wd)
    stdout, stderr = P.communicate()

    print_verbose('Done')
    if P.returncode:
        if not quiet:
            print('Command {0}'.format(cmd))
            print('Failed {0}'.format(stderr))
        if raise_error:
            raise CommandError(stderr)
    return stdout


def find_repo_top():
    """
    look for ".repo" in parent directory
    """
    if os.path.isdir('.repo'):
        return True

    lookdir = os.getcwd()
    while not os.path.isdir(os.path.join(lookdir, '.repo')):
        newlookdir = os.path.dirname(lookdir)
        if lookdir == newlookdir:
            print('no repo found {0}'.format(lookdir))
            return False
        lookdir = newlookdir
    os.chdir(lookdir)
    return True


def querygerrit(rev):
    """
    Query gerrit server for a list of gerrit patch ID.
    return a list of a json parsed data
    """
    cmd = ["ssh", "-f", "android.intel.com", "gerrit", "query", "--format=json",
           '--current-patch-set', '--patch-sets', '--commit-message'] + rev

    print_verbose('Start Gerrit Query {0}'.format(' '.join(cmd)))
    p = subprocess.Popen(args=cmd,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    print_verbose('Done')

    if p.returncode:
        print('Fetch failed {0}'.format(stderr))

    ret = [json.loads(s) for s in stdout.strip().split('\n')]
    del ret[-1]
    return ret


def gerrit_review(projs, review):
    """
    Query set the review flag on a list of patches
    """

    sha1_list = []
    gerrit_list = []
    for p in projs.values():
        for r in p:
            gerrit_list.append(r['number'])
            sha1_list.append(r['currentPatchSet']['revision'])

    print('reviewing gerrit id: {}'.format(' '.join(gerrit_list)))

    cmd = ["ssh", "-f", "android.intel.com", "gerrit", "review"] + review.split() + sha1_list

    print_verbose('Start Gerrit Query {0}'.format(' '.join(cmd)))

    p = subprocess.Popen(args=cmd,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    print_verbose('Done')

    if p.returncode:
        print('Gerrit review failed {0}'.format(stderr))

    return p.returncode


def populate_extra_g2p():

    cp = ConfigParser.SafeConfigParser()
    cp.optionxform = str
    fn = os.path.join(os.path.dirname(sys.argv[0]), "extra_g2p.cfg")
    if os.path.exists(fn):
        with open(fn) as fp:
            cp.readfp(fp)
        if cp.has_section("mapping"):
            for g, p in cp.items("mapping"):
                print_verbose('Add extra g2p {}:{}'.format(g, p))
                g2p[g] = p


def init_gerrit2path():
    """
    Generate a dictionary to convert gerrit project name
    to repo relative path using repo list
    """
    d = call('.', ['repo', 'list']).strip()

    for l in d.split('\n'):
        p, g = l.split(':')
        g2p[g.strip()] = p.strip()

    populate_extra_g2p()


def set_deps(r, g):
    """
    find gerrit depency of each patch
    """
    if 'parents' in r['currentPatchSet']:
        for r2 in g:
            for ps in r2['patchSets']:
                if ps['revision'] in r['currentPatchSet']['parents']:
                    if 'deps' not in r2:
                        set_deps(r2, g)
                    r['deps'] = [r2['number']] + r2['deps']
                    r['order'] = r2['order'] + 1
                    return
    r['deps'] = []
    r['order'] = g.index(r) * 1000


def split_by_project(gjson):
    """
    split gerrit json output by git project
    """
    projs = {}
    for r in gjson:
        p = g2p.get(str(r['project']), 'not_in_manifest')
        if p in projs:
            projs[p].append(r)
        else:
            projs[p] = [r]

    # to sort dependent patches
    for p in projs:
        g = projs[p]
        for r in g:
            set_deps(r, g)
        projs[p].sort(key=lambda r: r['order'])
    return projs


def query_gerrit_revision(grev, pset):
    """
    Generate 1 query for all requested gerrit revision
    eg: 111453 OR 123433 OR 115533
    grev: list of gerrit revision number to query
    return a dictionary with {project_path: [ gerjson1, gerjson2, ..]}
    """
    gjson = querygerrit(' OR '.join(grev).split())

    # to sort the list in the same order as grev
    gjson.sort(key=lambda r: grev.index(r['number']))

    projs = split_by_project(gjson)
    for p in projs:
        for r in projs[p]:
            grev.remove(r['number'])
            if r['number'] in pset:
                r['force_patchset'] = pset[r['number']]

    if grev:
        print('skipping {0} not found on gerrit, or project not present in '
              'manifest'.format(' '.join(grev)))
    return projs


def query_gerrit_custom(query):
    gjson = querygerrit(query.split())
    return split_by_project(gjson)


def set_repo_manifest(mname):
    """
    Synchronize repo with a specific manifest
    mname is the manifest name in .repo/manifests/ directory
    """
    print('initialize repository')
    call('.', ['repo', 'init', '-m', mname])
    print('synchronize repository (may take a while)')
    call('.', ['repo', 'sync', '-l', '-d', '-c'])


def chpick_one(p, r):
    """
    cherry pick one commit
    p is project, r is gerrit json for this patch
    logchid is used to check if patches is already applied
    """
    patch_name = '{0}/{1}'.format(r['number'], r['pset'])

    if r['isApplied'] == 'Applied':
        return '\t{0}\tAlready applied\n'.format(patch_name)

    # to apply patch
    try:
        call(p, ['git', 'cherry-pick', '--ff', r['ltag']], quiet=True)

    except CommandError:
        global status
        status = -1
        call(p, ['git', 'cherry-pick', '--abort'], quiet=True,
             raise_error=False)

        log = '\t{0}\tCouldn\'t be applied on {1}\n'.format(patch_name, p)
        if altmsg:
            log += '\t\t\tYou can reproduce the conflict with:\n'
            log += '\t\t\t{0}'.format(os.path.basename(__file__))
            log += ' {0}\n'.format(' '.join(r['deps'] + [r['number']]))
            return log

        if r['deps']:
            log += '\t\t\tdependencies {0}\n'.format(' '.join(r['deps']))
        log += '\t\t\tYou can resolve this conflict with:\n'
        log += '\t\t\t$ cd {0}\n'.format(p)
        log += '\t\t\t$ git cherry-pick {0}\n'.format(r['ltag'])
        log += '\t\t\t$ git mergetool\n'
        return log
    return '\t{0}\tApplied\n'.format(patch_name)


def get_log_chid(p, g):
    """
    use git log to check if this Change-Id already exist in the log, which
    means the patch is already applied.
    we limit the log to 2000 commits, or it can be very slow.
    """
    if p == 'not_in_manifest':
        return []

    grepcmd = ['git', 'log', '-n', '2000', '--format=%b']
    msg = call(p, grepcmd).decode('utf8', 'ignore')
    cid = [l for l in msg.split('\n') if l.startswith('Change-Id: ')]
    return [r['id'] for r in g for l in cid if l.find(r['id']) > 0]


def fetch_tags(p, g, sem):
    """
    fetch only required gerrit patches
    save them to a local tag (gerrit-40-147340-5)
    so we can avoid later git fetch, if the local tag is already present.
    """
    ref_to_fetch = []
    all_tags = call(p, ['git', 'tag', '-l', 'gerrit-*']).split()
    for r in g:
        if 'force_patchset' in r:
            r['pset'] = r['force_patchset']
            ref = 'refs/changes/{0}/{1}/{2}'.format(r['number'][-2:],
                                                    r['number'], r['pset'])
        else:
            ref = r['currentPatchSet']['ref']
            r['pset'] = ref.split('/')[-1]
        ltag = ref.replace('/', '-')
        ltag = ltag.replace('refs-changes', 'gerrit')
        r['ltag'] = ltag
        if ltag not in all_tags:
            ref_to_fetch.append('+{0}:refs/tags/{1}'.format(ref, ltag))

    remotes = call(p, ['git', 'remote']).split()
    if 'origin' not in remotes:
        r = 'ssh://android.intel.com/{0}'.format(g[0]['project'])
        print_verbose('{0}: Add origin remote: {1}'.format(p, r))
        call(p, ['git', 'remote', 'add', 'origin', r])
    # take a semaphore when fetching a branch, to avoid
    # too much request to the server in parallel
    if ref_to_fetch:
        with sem:
            call(p, ['git', 'fetch', remote] + ref_to_fetch)


def chpick_threaded(p, g, brname, lock, sem):
    """
    Check local branches
    """
    if brname:
        all_branch = call(p, ['git', 'branch']).split()
        if brname in all_branch:
            call(p, ['git', 'checkout', brname])
        else:
            call(p, ['git', 'checkout', '-b', brname])

    fetch_tags(p, g, sem)
    log = 'Project {0}\n'.format(p)
    for r in g:
        log += chpick_one(p, r)
    with lock:
        print(log)
        print


def chpick(projs, brname):
    """
    fetch and cherry-pick all gerrit inspection.
    projs: list of gerrit projects with patch revision number
    brname: branchname to create
    semaphore is to limit to 5 threads to do git fetch in parallel
    """
    allth = []
    lock = threading.Lock()
    sem = threading.Semaphore(5)

    for p in projs:
        g = projs[p]
        if p == 'not_in_manifest':
            print('ignoring revision {0}'
                  .format([int(r['number']) for r in g]))
            continue

        th = threading.Thread(None, chpick_threaded, None,
                              (p, g, brname, lock, sem), None)
        th.start()
        allth.append(th)

    for th in allth:
        th.join()


def get_bug_url(msg):
    """
    get BZ number/ Jira url from commit message
    """
    for l in msg.split('\n'):
        if l[0:3] == 'BZ:':
            bznum = l[4:]
            if bznum.isdigit():
                return [bznum,
                        'http://shilc211.sh.intel.com:41006'
                        '/show_bug.cgi?id={0}'.format(bznum)]
        if l[0:11] == 'Tracked-On:':
            url = l[11:]
            bugname = url.split('/')[-1]
            return [bugname, url]
    return ['', '']


def review_add(x, y):
    """
    adding review value is a hard task
    +2 + -2 = -2 and +2 + +1 = +2
    """
    revtable = {'-2': 5, '2': 4, '-1': 3, '1': 2, '0': 1, '': 0}

    if revtable[x] > revtable[y]:
        return x

    return y


def parse_json_info(p, r, logchid):
    """
    add more user friendly info in json results
    """
    pretty_verify = {'1': unichr(10003), '0': '-', '': '-',
                     '-1': 'x'}
    pretty_review = {'-2': '-2', '-1': '-1', '0': ' 0', '1': '+1', '2': '+2',
                     '': '0'}

    r['lastpset'] = r['currentPatchSet']['ref'].split('/')[-1]
    if 'force_patchset' in r:
        r['curpset'] = r['force_patchset']
    else:
        r['curpset'] = r['lastpset']

    if r['id'] in logchid:
        r['isApplied'] = 'Applied'
    else:
        r['isApplied'] = 'Missing'

    r['bugname'], r['bugurl'] = get_bug_url(r['commitMessage'])
    if r['bugurl']:
        r['buglink'] = '=hyperlink("{0}";"{1}")'.format(r['bugurl'],
                                                        r['bugname'])
    else:
        r['buglink'] = ''

    r['path'] = p
    r['ownername'] = r['owner']['name']
    r['psetinfo'] = '{0}/{1}'.format(r['curpset'], r['lastpset'])
    r['link'] = '=hyperlink("{0}";"{1}")'.format(r['url'], r['number'])
    r['review'] = ''
    r['verified'] = ''

    if 'approvals' in r['currentPatchSet']:
        for ap in r['currentPatchSet']['approvals']:
            if ap['type'] == 'Code-Review':
                r['review'] = review_add(r['review'], ap['value'])
            elif ap['type'] == 'Verified':
                r['verified'] = review_add(r['verified'], ap['value'])
    r['codereview'] = pretty_review[r['review']]
    r['verified'] = pretty_verify[r['verified']]
    r['review'] = r['verified'] + ' ' + r['codereview']


def get_info(projs):
    """
    parse some information on the json and check if patches already applied
    """
    for p in projs:
        logchid = get_log_chid(p, projs[p])
        for r in projs[p]:
            parse_json_info(p, r, logchid)


def pr_csv(projs, outfile):
    """
    print a csv file, so you can import it in Libreoffice/Excel
    """
    with open(outfile, 'wb') as f:
        f.write('\t'.join(['Patch', 'URL', 'Review', 'Verified', 'Patchset',
                           'Latest Patchset', 'IsApplied', 'BZ',
                           'Project Dir', 'Status', 'Owner', 'Subject\n']))
        column = ['number', 'link', 'verified', 'codereview', 'curpset',
                  'lastpset', 'isApplied', 'buglink', 'path', 'status',
                  'ownername', 'subject']

        for p in projs:
            for r in projs[p]:
                line = u'{0}\n'.format('\t'.join([r[c] for c in column]))
                f.write(line.encode("UTF-8"))


def pr_long(projs):
    """
    print long information on each gerrit number
    """
    column = ['url', 'bugname', 'bugurl',
              'status', 'review', 'psetinfo', 'subject']

    max_width = {}
    for c in column:
        width = len(c)
        for p in projs:
            for r in projs[p]:
                if len(r[c]) > width:
                    width = len(r[c])
        max_width[c] = width + 2
    pretty_column = [c.center(max_width[c]) for c in column]
    print('|'.join(pretty_column))
    print('+'.join(['-' * max_width[c] for c in column]))
    for p in projs:
        print('[Project {0}]'.format(p))
        for r in projs[p]:
            print('|'.join([r[c].center(max_width[c]) for c in column]))


def pr_short(projs):
    """
    print short summary on each gerrit number
    """
    for p in projs:
        print('# Project {0}'.format(p))
        for r in projs[p]:
            print('{0} # {1}'.format(r['url'], r['subject']))


def pr_short_with_patchset(projs):
    """
    print short summary on each gerrit number
    """
    for p in projs:
        print('# Project {0}'.format(p))
        for r in projs[p]:
            print('{0}/{1} # {2}'.format(r['url'], r['curpset'], r['subject']))


def genpatch(projs, tfile, manifest):
    """
    generate .patch files, and put them in a tar archive.
    add current manifest to tar archive if asked to do so ( -m )
    """
    with tarfile.open(tfile, 'w') as f:
        if manifest:
            mname = os.path.relpath(os.path.realpath('.repo/manifest.xml'))
            print('ADD {0}'.format(mname))
            f.add(mname)

        # dummy semaphore (we're single-threaded when generating tarball
        sem = threading.Semaphore(5)

        for p in projs:
            g = projs[p]
            print('Project: {0}'.format(p))
            fetch_tags(p, g, sem)

            for r in g:
                try:
                    pname = call(p, ['git', 'format-patch', '-1', r['ltag'],
                                     '--start-number', r['number']]).strip()

                except CommandError:
                    print('Can\'t generate {0}'.format(tfile))
                    return -1

                pname = os.path.join(p, pname)
                patch_name = '{0}-{1}.patch'.format(r['number'], r['pset'])
                newname = os.path.join(p, patch_name)
                print('ADD {0}'.format(newname))
                f.add(pname, arcname=newname)
                os.remove(pname)

    print('{0} generated'.format(tfile))
    return 0


def applypatch(tfile):
    """
    extract files from tar archive and apply them
    if a manifest is present, set repo to this manifest.
    if patches apply, remove the .patch file
    if it fails, let it so user can apply it by hands
    """
    with tarfile.open(tfile, 'r') as f:
        def is_within_directory(directory, target):
            
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
        
            prefix = os.path.commonprefix([abs_directory, abs_target])
            
            return prefix == abs_directory
        
        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        
            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")
        
            tar.extractall(path, members, numeric_owner=numeric_owner) 
            
        
        safe_extract(f)

        allfiles = f.getnames()
        mname = [m for m in allfiles if '.xml' in m]
        if mname:
            set_repo_manifest(os.path.basename(mname[0]))
            allfiles.remove(mname[0])

        for patch in allfiles:
            p, fname = os.path.split(patch)
            try:
                call(p, ['git', 'am', '-3', '--keep-cr',
                         '--whitespace=nowarn', fname])
                print('{0}\t\t\tApplied'.format(patch))
                os.remove(patch)

            except CommandError:
                print('{0}\t\t\tFAILED'.format(patch))
                call(p, ['git', 'am', '--abort'])
                return -1

    return 0


def clean_args(args):
    """
    clean arguments given
    https://android.intel.com/#/c/149140/5 to 149140 pset 5
    remove duplicate
    """
    grev = []
    pset = {}
    blacklist = []

    for a in args:
        l = a.strip().rstrip('/').split('/')
        # to handle patchset revision (ie xxxxx/x)
        if len(l) > 1 and l[-1].isdigit() and l[-2].isdigit():
            if not l[-2] in grev:
                grev.append(l[-2])
                pset[l[-2]] = l[-1]
        elif len(l) > 0 and l[-1].isdigit():
            blacklist.append(l[-1])
            #if not l[-1] in grev:
            #    grev.append(l[-1])
        else:
            print('Parsing error {0}'.format(a))
            print('You can comment this line using #')

    if blacklist:
        print("autopatch.py error: patch id:{} need specify patch set number !!!".format(blacklist))
        sys.exit(1)

    return grev, pset


def parse_infile(fnames):
    """
    parse input file
    """
    args = []
    finc = []
    for fname in fnames:
        with open(fname, 'r') as f:
            c = f.read()
            for l in c.split('\n'):
                l = l.replace('/#/', '/')
                comment = l.find('#')
                if comment > -1:
                    l = l[0:comment]
                l = l.strip().rstrip('/')
                if l:
                    if l.find('include') > -1:
                        finc.append(os.path.dirname(fname)+'/'+l.split()[1])
                    else:
                        args.append(l)
    return args, finc


verbose = False
altmsg = False
g2p = {}
remote = None
status = 0


def main():

    usage = "usage: %prog [options] patch1 patch2 ... "
    description = ("Genereric tool to manage a list of patches from gerrit. "
                   "The default behavior is to apply the patches to current "
                   "repository")
    parser = OptionParser(usage, description=description)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose")
    parser.add_option("-b", "--branch", dest="brname", default='',
                      help=("create branch BRNAME or checkout BRNAME before"
                            "cherry-pick"))
    parser.add_option("-e", "--remote", dest="remote", default=None,
                      help=("force the remote host to fetch from. "
                            "default is to use the first in the list given by"
                            " `git remote`"))
    parser.add_option("-f", "--file", dest="infile",
                      help="read gerrit id from files instead of arguments."
                           " Multiple files can be specified",
                      action="append")
    parser.add_option("-c", "--csv", dest="csvfile",
                      help=("write gerrit information on the list of file to"
                            " a csv file"))
    parser.add_option("-s", "--short", dest="printshort", action='store_true',
                      help="print patches short status")
    parser.add_option("-p", "--short-ps", dest="printshortp",
                      action='store_true', help="print patches short status "
                      "with patchset")
    parser.add_option("-l", "--long", dest="printlong", action='store_true',
                      help="print patches long status")
    parser.add_option("-g", "--genpatch", dest="genpatch",
                      help="save patches to a tar file")
    parser.add_option("-a", "--applypatch", dest="applypatch",
                      help="apply all patches saved to a tar file")
    parser.add_option("-m", "--manifest", dest="manifest", action='store_true',
                      help=("when used with -g, add the manifest.xml to "
                            "the tar file"))
    parser.add_option("-q", "--query", dest="query",
                      help=("free form gerrit query, like topic:l_64bits or "
                            "is:starred"))
    parser.add_option("-r", "--save-query", dest="save_query",
                      help=("save gerrit query to file"))
    parser.add_option("-t", "--load-query", dest="load_query",
                      help=("use a file instead of doing a query on gerrit"))
    parser.add_option("-u", "--alternate-chpick-msg", dest="altmsg",
                      action="store_true",
                      help=("change output when a patch failed to apply"))
    parser.add_option("-w", "--review", dest="review", default=None,
                      help=("set the review flag ex --code-review=+1"))

    (options, args) = parser.parse_args()

    # find_repo_top() will change current directory, to the repo top directory
    # save current directory in start_folder
    start_folder = os.getcwd()

    if options.verbose:
        global verbose
        verbose = True

    if options.altmsg:
        global altmsg
        altmsg = True

    if not (options.infile or options.query or options.load_query
            or options.applypatch):
        if len(args) < 1:
            parser.print_help()
            return -1

    if options.infile:
        infile = options.infile
        while True:
            rargs, rfinc = parse_infile(infile)
            args += rargs
            if len(rfinc) == 0:
                break
            else:
                infile = rfinc

    if not find_repo_top():
        print('Can\'t find .repo folder')
        return -1

    if options.applypatch:
        fname = os.path.join(start_folder, options.applypatch)
        return applypatch(fname)

    init_gerrit2path()

    if options.load_query:
        fname = os.path.join(start_folder, options.load_query)
        with open(fname, 'r') as f:
            projs = eval(f.read())
    elif options.query:
        projs = query_gerrit_custom(options.query)
    else:
        grev, pset = clean_args(args)
        if not grev:
            print('No patches to process, exiting (use -h for help)')
            return 0
        projs = query_gerrit_revision(grev, pset)

    if options.save_query:
        fname = os.path.join(start_folder, options.save_query)
        with open(fname, 'w') as f:
            f.write(repr(projs))
        return 0

    if not projs:
        print('No patches to process, exiting (use -h for help)')
        return 0

    get_info(projs)

    if options.csvfile:
        fname = os.path.join(start_folder, options.csvfile)
        pr_csv(projs, fname)
        return 0

    if options.printshort:
        pr_short(projs)
        return 0

    if options.printshortp:
        pr_short_with_patchset(projs)
        return 0

    if options.printlong:
        pr_long(projs)
        return 0

    global remote
    if options.remote:
        remote = options.remote
    else:
        remote = call(projs.keys()[0], ['git', 'remote']).strip().split()[0]

    if options.genpatch:
        fname = os.path.join(start_folder, options.genpatch)
        return genpatch(projs, fname, options.manifest)

    if options.review:
        return gerrit_review(projs, options.review)

    chpick(projs, options.brname)

    return status

if __name__ == "__main__":
    exit(main())

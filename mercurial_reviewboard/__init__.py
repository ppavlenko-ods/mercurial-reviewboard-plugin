'''post changesets to a reviewboard server'''

import operator
import os
import re
import sys
import tempfile

from mercurial import hg, mdiff, patch, util, commands, error, registrar
from mercurial.commands import bundle, unbundle
from mercurial.i18n import _
from mercurial.node import (hex, nullid)
from mercurial.utils import dateutil, urlutil

from .hgversion import HgVersion
from .reviewboard import make_rbclient, ReviewBoardError
from .utils import cmp

__version__ = '5.0.0'

cmdtable = {}
command = registrar.command(cmdtable)

BUNDLE_ATTACHMENT_CAPTION = 'changeset bundle'


@command(b'pullreviewed',
         [(b's', b'submit', False, str.encode('if unbundle is successfull, mark the review as submitted (implies '
                                              '--unbundle)')),
          (b'I', b'interactive', False, str.encode('override the default summary and description')),
          (b'u', b'unbundle', False, str.encode('unbundle the downloaded bundle')),
          (b'O', b'outgoingrepo', b'', str.encode('use specified repository to determine which reviewed bundles to pull'))],
         str.encode('hg pullreviewed '))
def get_shipable_bundles(ui, repo, rev='.', **opts):
    """TBD
    """
    ui.status(str.encode('postreview plugin, version %s' % __version__))
    find_server(ui, opts)
    reviewboard = getreviewboard(ui, opts)
    opts['unbundle'] = opts['submit'] or opts['unbundle']
    try:
        repo_id = find_reviewboard_repo_id(ui, reviewboard, opts)
        shipable = reviewboard.shipable_requests(repo_id)
        fnames_per_request = [
            (reviewboard.download_attachement_with_given_caption(request.id, BUNDLE_ATTACHMENT_CAPTION), request.id) for
            request in shipable]
        if opts['unbundle']:
            for fnames, request_id in fnames_per_request:
                [unbundle(ui, repo, fname) for fname in fnames]
                if opts['submit']:
                    reviewboard.submit(request_id)
                    ui.status(b'submitted')
    except ReviewBoardError as msg:
        raise error.Abort(str.encode(str(msg)))


@command(b'fetchreviewed',
         [(b'n', b'dry-run', False,
           str.encode("Perform the fetch, but do not modify remote resources (reviewboard and repositories)"))],
         str.encode('hg fetchreviewed [-p]'))
def fetch_reviewed(ui, repo, **opts):
    """fetch approved changes from reviewboard and apply to relevant repository.

    This command is intended to be run as part of automated process, that
    imports approved changes from review board.

    It will download bundles, attached to review requests, marked as 'ship-it'
    and import them into working repository. If import results in additional
    head, automatic merge will be attempted.

    If any problems are encountered during bundle import, review request will
    be updated with problem description and further import will not be
    attempted until problem is fixed.

    Operation supports reviews from multiple repositories (of mercurial type).

    Note, that this command will strip all outgoing changes out of working
    repo. This is required  to get a clean clone of remote repo before import.
    """
    from .fetchreviewed import fetchreviewed
    fetchreviewed(ui, opts)


@command(b'postreview',
         [(b'o', b'outgoing', True, str.encode('use upstream repository to determine the parent diff base')),
          (b'O', b'outgoingrepo', b'', str.encode('use specified repository to determine the parent diff base')),
          (b'i', b'repoid', b'', str.encode('specify repository id on reviewboard server')),
          (b's', b'summary', b'', str.encode('specify a summary for the review request')),
          (b'm', b'master', b'', str.encode('use specified revision as the parent diff base')),
          (b'', b'server', b'', str.encode('ReviewBoard server URL')),
          (b'e', b'existing', b'', str.encode('existing request ID to update')),
          (b'u', b'update', False, str.encode('update the fields of an existing request')),
          (b'p', b'publish', None, str.encode('publish request immediately')),
          (b'', b'parent', b'', str.encode('parent revision for the uploaded diff')),
          (b'g', b'outgoingchanges', True, str.encode('create diff with all outgoing changes')),
          (b'b', b'branch', False, str.encode('create diff of all revisions on the branch')),
          (b'I', b'interactive', False, str.encode('override the default summary and description')),
          (b'U', b'target_people', b'', str.encode('comma separated list of people needed to review the code')),
          (b'G', b'target_groups', b'', str.encode('comma separated list of groups needed to review the code')),
          (b'B', b'bugs_closed', b'', str.encode('comma separated list of bug IDs addressed by the change')),
          (b'', b'username', b'', str.encode('username for the ReviewBoard site')),
          (b'', b'password', b'', str.encode('password for the ReviewBoard site')),
          (b'a', b'attachbundle', True,
           str.encode('Attach the changeset bundle as a file in order to pull it with pullreviewed')),
          (b'', b'old_server', False, str.encode(
              'Send v1 Bundle format if your ReviewBoard install has old Mercurial that does not recognize bundle2 '
              'format.'))],
         str.encode('hg postreview [OPTION]... [REVISION]'))
def postreview(ui, repo, rev='.', **opts):
    '''post a changeset to a Review Board server

This command creates a new review request on a Review Board server, or updates
an existing review request, based on a changeset in the repository. If no
revision number is specified the parent revision of the working directory is
used.

By default, the diff uploaded to the server is based on the parent of the
revision to be reviewed. A different parent may be specified using the
--parent option.  Alternatively you may specify --outgoingchanges to calculate
the parent based on the outgoing changesets or --branch to choose the parent
revision of the branch.

If the parent revision is not available to the Review Board server (e.g. it
exists in your local repository but not in the one that Review Board has
access to) you must tell postreview how to determine the base revision
to use for a parent diff. The --outgoing, --outgoingrepo or --master options
may be used for this purpose. The --outgoing option is the simplest of these;
it assumes that the upstream repository specified in .hg/hgrc is the same as
the one known to Review Board. The other two options offer more control if
this is not the case.

The --outgoing option recognizes the path entries 'reviewboard', 'default-push'
and 'default' in this order of precedence. 'reviewboard' may be used if the
repository accessible to Review Board is not the upstream repository.
'''

    '''
HG issue 3841 workaround
https://bitbucket.org/tortoisehg/thg/issue/3841/reviewboard-extension-error-unknown
'''
    #oldin, oldout, olderr = sys.stdin, sys.stdout, sys.stderr
    # sys.stdin, sys.stdout, sys.stderr = ui.fin, ui.fout, ui.ferr
    #sys.stdin, sys.stderr = ui.fin, ui.ferr

    ui.status(str.encode('postreview plugin, version %s\n' % __version__))

    # checks to see if the server was set
    find_server(ui, opts)

    check_parent_options(opts)

    rev_no = repo.revs(rev).first()
    c = repo[rev_no]

    rparent = find_rparent(ui, repo, c, opts)
    ui.debug(str.encode('remote parent: %s\n' % rparent))

    parent = find_parent(ui, repo, c, rparent, opts)
    ui.debug(str.encode('parent: %s\n' % parent))

    if parent is None:
        msg = "Unable to determine parent revision for diff. "
        if opts.get('outgoingchanges'):
            msg += "If using -g/--outgoingchanges, make sure you have some (type 'hg out'). Did you forget to commit ('hg st')?"
        raise error.Abort(str.encode(str(msg)))
    diff, parentdiff = create_review_data(ui, repo, c, parent, rparent)

    send_review(ui, repo, c, parent, diff, parentdiff, opts)

    #sys.stdin, sys.stdout, sys.stderr = oldin, oldout, olderr


def find_rparent(ui, repo, c, opts):
    outgoing = opts.get('outgoing')
    outgoingrepo = opts.get('outgoingrepo')
    master = opts.get('master')
    if master:
        master_no = repo.revs(master).first()
        rparent = repo[master_no]
    elif outgoingrepo:
        rparent = remoteparent(ui, repo, opts, c, upstream=outgoingrepo)
    elif outgoing:
        rparent = remoteparent(ui, repo, opts, c)
    else:
        rparent = None
    return rparent


def find_parent(ui, repo, c, rparent, opts):
    parent = opts.get('parent')
    outgoingchanges = opts.get('outgoingchanges')
    branch = opts.get('branch')

    if outgoingchanges:
        parent = rparent
    elif parent:
        parent = repo[parent]
    elif branch:
        parent = find_branch_parent(ui, c)
    else:
        parent = c.parents()[0]
    return parent


def create_review_data(ui, repo, c, parent, rparent):
    'Returns a tuple of the diff and parent diff for the review.'
    diff = getdiff(ui, repo, c, parent)
    ui.debug(b'\n=== Diff from parent to rev ===\n')
    ui.debug(str.encode(diff) + b'\n')

    if rparent != None and parent != rparent:
        parentdiff = getdiff(ui, repo, parent, rparent)
        ui.debug(b'\n=== Diff from rparent to parent ===\n')
        ui.debug(str.encode(parentdiff) + b'\n')
    else:
        parentdiff = ''
    return diff, parentdiff


def send_review(ui, repo, c, parentc, diff, parentdiff, opts):
    files = None
    if opts['attachbundle']:
        tmpfile = tempfile.NamedTemporaryFile(prefix='review_', suffix='.hgbundle', delete=False)
        tmpfile.close()
        if opts['old_server']:
            ui.status(str.encode('postreview using old server compatibility mode (bundle format v1)\n'))
            # request explicit 'v1' bundle format for our old creaky reviewboard server (running mercurial 2.0.x)
            # because it would be unable to read new 'v2' bundle format that mercurial 3.x uses
            bundle(ui, repo, tmpfile.name, dest=None, base=(parentc.rev(),), rev=(c.rev(),), type='bzip2-v1')
        else:
            bundle(ui, repo, tmpfile.name, dest=None, base=(parentc.rev(),), rev=(c.rev(),))

        f = open(tmpfile.name, 'rb')
        files = {BUNDLE_ATTACHMENT_CAPTION: {'filename': tmpfile.name, 'content': f.read()}}
        f.close()
        os.remove(tmpfile.name)

    fields = createfields(ui, repo, c, parentc, opts)

    request_id = opts['existing']
    if request_id:
        update_review(request_id, ui, fields, diff, parentdiff, opts, files)
    else:
        request_id = new_review(ui, fields, diff, parentdiff,
                                opts, files)
    if type(request_id) == bytes:
        request_id = request_id.decode('utf-8')
    request_url = '%s/r/%s/' % (find_server(ui, opts).decode('utf-8'), request_id)
    if not request_url.startswith('http'):
        request_url = 'http://%s' % request_url

    msg = 'review request draft saved: %s\n'
    if opts['publish']:
        msg = 'review request published: %s\n'
    ui.status(str.encode(msg % request_url))
    if ui.configbool(b'reviewboard', b'launch_webbrowser'):
        launch_webbrowser(ui, request_url)


def launch_webbrowser(ui, request_url):
    # not all python installations have this module, so only import it
    # when it's used
    from mercurial import demandimport
    demandimport.disable()
    import webbrowser
    demandimport.enable()

    # ui.status('browser launched\n')
    webbrowser.open(request_url)


def getdiff(ui, repo, r, parent):
    '''return diff for the specified revision'''
    output = ""

    # the following is for Git style commit (similarly as in cmdutil.export, previously patch.export command)

    ctx = repo[r.node()]
    node = ctx.node()
    parents = [p.node() for p in ctx.parents() if p]
    branch = ctx.branch()

    if parents:
        prev = parents[0]
    else:
        prev = nullid

    output += "# HG changeset patch\n"
    output += "# User %s\n" % ctx.user().decode('utf-8')
    output += "# Date %d %d\n" % ctx.date()
    output += "#      %s\n" % dateutil.datestr(ctx.date()).decode('utf-8')
    if branch and branch != 'default':
        output += "# Branch %s\n" % branch.decode('utf-8')
    output += "# Node ID %s\n" % hex(node).decode('utf-8')
    if len(parents) > 1:
        output += "# Parent  %s\n" % hex(parents[1]).decode('utf-8')
    output += "# Parent  %s\n" % hex(parent.node()).decode('utf-8')
    output += ctx.description().rstrip().decode("utf-8")
    output += "\n\n"

    opts = mdiff.defaultopts
    opts.git = True
    for chunk in patch.diff(repo, parent.node(), r.node(), opts=opts):
        output += chunk.decode("utf-8")
    return output


def getreviewboard(ui, opts):
    '''We are going to fetch the setting string from hg prefs, there we can set
    our own proxy, or specify 'none' to pass an empty dictionary to urllib2
    which overides the default autodetection when we want to force no proxy'''
    http_proxy = ui.config(b'reviewboard', b'http_proxy')
    if http_proxy:
        if http_proxy == 'none':
            proxy = {}
        else:
            proxy = {'http': http_proxy}
    else:
        proxy = None

    server = find_server(ui, opts)
    ui.status(str.encode('reviewboard:\t%s\n' % server))
    ui.status(b'\n')
    username = opts.get(b'username') or ui.config(b'reviewboard', b'user')
    if username:
        ui.status(str.encode('username: %s\n' % username))
    password = opts.get(b'password') or ui.config(b'reviewboard', b'password')
    if password:
        ui.status(str.encode('password: %s\n' % '**********'))
    api_token = opts.get(b'api_token') or ui.config(b'reviewboard', b'api_token')
    try:
        return make_rbclient(server, username, password, proxy=proxy, api_token=api_token)
    except ReviewBoardError as msg:
        raise error.Abort(str.encode(str(msg)))


def update_review(request_id, ui, fields, diff, parentdiff, opts, files=None):
    reviewboard = getreviewboard(ui, opts)

    try:
        reviewboard.delete_attachments_with_caption(request_id, BUNDLE_ATTACHMENT_CAPTION)
        reviewboard.update_request(request_id, fields, diff, parentdiff, files)
        if opts['publish']:
            reviewboard.publish(request_id)
    except ReviewBoardError as msg:
        raise error.Abort(str.encode(str(msg)))


def new_review(ui, fields, diff, parentdiff, opts, files=None):
    reviewboard = getreviewboard(ui, opts)
    repo_id = find_reviewboard_repo_id(ui, reviewboard, opts)

    try:
        request_id = reviewboard.new_request(repo_id, fields, diff, parentdiff, files)
        if opts['publish']:
            reviewboard.publish(request_id)
    except ReviewBoardError as msg:
        raise error.Abort(str.encode(str(msg)))
    return request_id


def find_reviewboard_repo_id(ui, reviewboard, opts):
    if opts.get('repoid'):
        return opts.get('repoid')
    elif ui.config(b'reviewboard', b'repoid'):
        return ui.config(b'reviewboard', b'repoid')
    try:
        repositories = reviewboard.repositories()
    except ReviewBoardError as msg:
        raise error.Abort(str.encode(str(msg)))
    if not repositories:
        raise error.Abort(str.encode('no repositories configured at %s' % find_server(ui, opts)))

    # repositories = sorted(repositories, key=operator.attrgetter('name'),
    #                       cmp=lambda x, y: cmp(x.lower(), y.lower()))

    remotepath = remove_username(expandpath(ui, opts['outgoingrepo']).lower())
    repo_id = None
    for r in repositories:
        if r.tool != 'Mercurial':
            continue
        if is_same_repo(r.path, remotepath.decode('utf-8')):
            repo_id = str(r.id)
            ui.status(str.encode('Using repository: %s\n' % r.name))
            break
    if repo_id == None and opts['interactive']:
        ui.status(b'Repositories:\n')
        repo_ids = set()
        for r in repositories:
            if r.tool != 'Mercurial':
                continue
            ui.status(str.encode('[%s] %s\n' % (r.id, r.name)))
            repo_ids.add(str(r.id))
        if len(repositories) > 1:
            repo_id = ui.prompt(b'repository id:', 0)
            if not repo_id in repo_ids:
                raise error.Abort(str.encode('invalid repository ID: %s' % repo_id))
        else:
            repo_id = str(repositories[0].id)
            ui.status('repository id: %s\n' % repo_id)
    elif repo_id == None and not opts['interactive']:
        raise error.Abort(str.encode('could not determine repository - use interactive flag'))
    return repo_id


"""
Removes the user name, if one has been provided in repo_path URL (such as 'https://username@hg.example.org').
This often occurs when using keyring for storing remote repo passwords, etc.
Returns the repo path without user name, suitable for comparing with reviewboard's repository list.
"""


def remove_username(repo_path):
    username_pos = repo_path.find(b'@')
    if username_pos == -1:
        return repo_path
    protocol_pos = repo_path.index(b'://') + 3
    return repo_path[:protocol_pos] + repo_path[username_pos + 1:]


def is_same_repo(path1, path2):
    if not path1.endswith('/'):
        path1 += '/'

    if not path2.endswith('/'):
        path2 += '/'

    return path1.lower() == path2.lower()


def createfields(ui, repo, c, parentc, opts):
    fields = {}

    all_contexts = find_contexts(repo, parentc, c, opts)
    # The latest unambiguous prefix of global changeset id (Commit field on UI)
    # Should be set on creation and on any update of review request.
    # commit_id field is introduced in reviewboard API 2.0
    fields['commit_id'] = str(all_contexts[0])
    changesets_string = 'changesets:\n'
    changesets_string += \
        ''.join(['\t%s:%s "%s"\n' % (ctx.rev(), ctx, ctx.description().decode("utf-8")) \
                 for ctx in all_contexts])
    if opts['branch']:
        branch_msg = "review of branch: %s\n\n" % (c.branch())
        changesets_string = branch_msg + changesets_string
    ui.status(str.encode(changesets_string + '\n'))

    interactive = opts['interactive']
    request_id = opts['existing']
    # Don't clobber the summary and description for an existing request
    # unless specifically asked for    
    if opts['update'] or not request_id:

        # summary
        if opts["summary"] and opts["summary"] != " ":
            default_summary = opts["summary"]
        else:
            default_summary = c.description().splitlines()[0]

        if interactive:
            ui.status(str.encode('default summary: %s\n' % default_summary))
            ui.status(str.encode('enter summary (or return for default):\n'))
            summary = readline().strip()
            if summary:
                fields['summary'] = summary
            else:
                fields['summary'] = default_summary
        else:
            fields['summary'] = default_summary.decode("utf-8")

        # description
        if interactive:
            ui.status(str.encode('enter description:\n'))
            description = readline().strip()
            ui.status(str.encode('append changesets to description? (Y/n):\n'))
            choice = readline().strip()
            if choice != 'n':
                if description:
                    description += '\n\n'
                description += changesets_string
        else:
            description = changesets_string
        fields['description'] = description
        if not opts.get('bugs_closed') and fields['summary']:
            summary = fields['summary']
            if type(summary) == bytes:
                summary = summary.decode("utf-8")
            bugs_list = re.findall(r'([A-Z]+-[0-9]+)', summary)
            bugs_list = list(set(bugs_list))
            augumented_bugs_list = []
            for bug in bugs_list:
                if bug is bugs_list[-1]:
                    augumented_bugs_list.append(str(bug))
                else:
                    augumented_bugs_list.append(str(bug) + ", ")

            fields['bugs_closed'] = "".join(augumented_bugs_list)
        fields['branch'] = c.branch().decode("utf-8")

    for field in ('target_groups', 'target_people', 'bugs_closed'):
        if opts.get(field):
            value = opts.get(field)
        else:
            value = ui.config(b'reviewboard', str.encode(field))
        if value:
            fields[field] = value.decode("utf-8")

    return fields


def remoteparent(ui, repo, opts, ctx, upstream=None):
    remotepath = expandpath(ui, upstream)
    remoterepo = hg.peer(repo, opts, remotepath)
    # if HgVersion(util.version().decode("utf-8")) >= HgVersion('2.1'):
    #     remoterepo = hg.peer(repo, opts, remotepath)
    # else:
    #     remoterepo = hg.repository(ui, remotepath)
    out = findoutgoing(repo, remoterepo)
    for o in out:
        orev = repo[o]
        a, b, c = repo.changelog.nodesbetween([orev.node()], [ctx.node()])
        if a:
            return orev.parents()[0]


def findoutgoing(repo, remoterepo):
    # The method for doing this has changed a few times...
    try:
        from mercurial import discovery
    except ImportError:
        # Must be earlier than 1.6
        return repo.findoutgoing(remoterepo)

    try:
        outgoing = discovery.findcommonoutgoing(repo, remoterepo)
        return outgoing.missing
        # if HgVersion(util.version()) >= HgVersion('2.1'):
        #     outgoing = discovery.findcommonoutgoing(repo, remoterepo)
        #     return outgoing.missing
        common, outheads = discovery.findcommonoutgoing(repo, remoterepo)
        return repo.changelog.findmissing(common=common, heads=outheads)

    except AttributeError:
        # Must be earlier than 1.9
        return discovery.findoutgoing(repo, remoterepo)


def expandpath(ui, upstream):
    if upstream:
        return ui.expandpath(upstream)
    else:
        res = urlutil.get_unique_push_path('postreview',None, ui)
        return res.rawloc


def check_parent_options(opts):
    usep = bool(opts['parent'])
    useg = bool(opts['outgoingchanges'])
    useb = bool(opts['branch'])

    if (usep or useg or useb) and not (usep ^ useg ^ useb):
        raise error.Abort(str.encode(
            "you cannot combine the --parent, --outgoingchanges "
            "and --branch options"))

    if useg and not (opts.get('outgoing') or opts.get('outgoingrepo')):
        msg = ("When using the -g/--outgoingchanges flag, you must also use "
               "either the -o or the -O <repo> flag.")
        raise error.Abort(msg)


def find_branch_parent(ui, ctx):
    '''Find the parent revision of the 'ctx' branch.'''
    branchname = ctx.branch()

    getparent = lambda ctx: ctx.parents()[0]

    currctx = ctx
    while getparent(currctx) and currctx.branch() == branchname:
        currctx = getparent(currctx)
        ui.debug('currctx rev: %s; branch: %s\n' % (currctx.rev(),
                                                    currctx.branch()))

    # return the root of the repository if the first
    # revision is on the branch
    if not getparent(currctx) and currctx.branch() == branchname:
        return currctx._repo[b'0000000000000000000000000000000000000000']

    return currctx


def find_contexts(repo, parentctx, ctx, opts):
    """Find all context between the contexts, excluding the parent context."""
    contexts = []
    for node in repo.changelog.nodesbetween([parentctx.node()], [ctx.node()])[0]:
        currctx = repo[node]
        if node == parentctx.node():
            continue
        # only show nodes on the current branch
        if opts['branch'] and currctx.branch() != ctx.branch():
            continue
        contexts.append(currctx)
    contexts.reverse()
    return contexts


def find_server(ui, opts):
    server = opts.get('server')
    if not server:
        server = ui.config(b'reviewboard', b'server')
    if not server:
        msg = 'please specify a reviewboard server in your .hgrc file or using the --server flag'
        raise error.Abort(str.encode(str(msg)))
    return server


def get_repositories(reviewboard):
    """Return list of registered mercurial repositories"""

    repos = reviewboard.repositories()
    return [r for r in repos if r.tool == 'Mercurial']


def readline():
    line = sys.stdin.readline()
    return line


if util.safehasattr(commands, 'optionalrepo'):
    commands.optionalrepo += ' fetchreviewed'

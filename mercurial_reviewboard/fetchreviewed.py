"""
Command to fetch approved changes from reviewboard and apply to relevant
repository.
"""
import base64
import datetime
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from mercurial import commands
from mercurial import hg
from mercurial import repair
from mercurial import util
# from mercurial.hgweb.webcommands import file
from mercurial.i18n import _

from .SingleRun import SingleRun
from .hgversion import HgVersion
from .reviewboard import ReviewBoardError


@SingleRun("fetchreviewed")
def fetchreviewed(ui, repo, **opts):
    from . import find_server, getreviewboard

    ui.status(str.encode("\n\nStarting fetchreview...\n"))
    ui.status(str.encode("%s\n" % str(datetime.datetime.now())))

    find_server(ui, opts)
    reviewboard = getreviewboard(ui, opts)

    rbrepos = get_repositories(reviewboard)

    for r in rbrepos:
        rf = ReviewFetcher(ui, reviewboard, r, opts)
        rf.fetch_reviewed()
        rf.fetch_pending()

    ui.status(str.encode("%s\n" % str(datetime.datetime.now())))
    ui.status(b"Finished fetchreview.\n")


def get_repositories(reviewboard):
    """Return list of registered mercurial repositories"""

    repos = reviewboard.repositories()
    return [r for r in repos if r.tool == 'Mercurial']


class ReviewFetcher(object):
    ui = None
    reviewboard = None
    rbrepo = None

    repo = None

    def __init__(self, ui, reviewboard, rbrepo, opts):
        self.ui = ui
        self.reviewboard = reviewboard
        self.rbrepo = rbrepo
        self.opts = opts

        self.dryrun = opts.get('dry_run', False)

    def fetch_reviewed(self):
        """Fetch changes into repository"""
        shipable = self.reviewboard.shipable_requests(self.rbrepo.id)
        if not shipable:
            self.ui.debug(str.encode("Nothing shipable found for repository %s\n" % self.rbrepo.name))
            return

        self.ui.status(str.encode("Processing shipped review requests for repo %s\n" % self.rbrepo.name))
        self.repo = self.get_local_repo()

        for request in shipable:
            self.ui.status(str.encode("Processing review request %s\n" % request.id))
            try:
                self.clean_working_copy()
                fetched = self.fetch_review_request(request)
                if fetched and not self.dryrun:
                    self.report_success(request)
                    self.update_jira(request, "Shipped")
                else:
                    self.ui.status(str.encode("Review request %s was not submitted \n" % request.id))
            except util.error.Abort as e:
                self.ui.status(str.encode("Processing of request %s failed (%s)\n" % (request.id, e.message)))
                if not self.dryrun:
                    self.report_failure(request, e)

    def fetch_pending(self):
        pending = self.reviewboard.pending_requests()
        if not pending:
            self.ui.debug(str.encode("Nothing pending found for repository %s\n" % self.rbrepo.name))
            return
        self.ui.debug(str.encode("Processing pending review requests for repo %s\n" % self.rbrepo.name))
        if os.path.exists("reviews.json"):
            infile = open("reviews.json", "r+")
            data = json.load(infile)
            reviews = data['reviews']
            request_id_exists = False
            new_reviews = []
            for request in pending:
                for review in reviews:
                    if request.id == review['id']:
                        request_id_exists = True
                        review = {'id': request.id, 'summary': request.summary}
                        new_reviews.append(review)
                        break
                if request_id_exists is False:
                    review = {'id': request.id, 'summary': request.summary}
                    new_reviews.append(review)
                    self.update_jira(request, "Pending")

            outfile = open("reviews.json", "w+")
            data = json.dumps({'reviews': new_reviews})
            outfile.write(data)
            outfile.close()
        else:
            outfile = open("reviews.json", "w+")
            reviews = []
            for request in pending:
                self.ui.status(str.encode("Processing review request %s\n" % request.id))
                review = {'id': request.id, 'summary': request.summary}
                reviews.append(review)
                self.update_jira(request, "Pending")
            data = json.dumps({'reviews': reviews})
            outfile.write(data)
            outfile.close()

    def get_local_repo(self):
        rname = self.rbrepo.name
        if not os.path.exists(rname):
            commands.clone(self.ui, str.encode(self.rbrepo.path), str.encode(rname))

        repo = hg.repository(self.ui, str.encode(rname))
        commands.pull(self.ui, repo, str.encode(self.rbrepo.path))
        return repo

    def fetch_review_request(self, request):
        bundles = self.reviewboard.download_attachement_with_given_caption(request.id, 'changeset bundle')
        if not bundles:
            self.ui.status(str.encode("Warning: no mercurial bundles were found in review request %s\n" % request.id))
            return False

        self.ui.status(str.encode("Bundles found: %s\n" % bundles))
        self.ui.pushbuffer()
        bundles_encoded=[s.encode() for s in bundles]
        try:
            try:
                self.ui.status(b"Apply bundle to local repository\n")
                commands.unbundle(self.ui, self.repo, *bundles_encoded)
            except LookupError as e:
                self.ui.status(str.encode("Cannot unbundle: %s\n" % e.message))
                raise util.error.Abort("Cannot unbundle: %s" % e.message)
        finally:
            self.ui.popbuffer()

        # find and merge any heads, introduced by importing bundle
        heads = self.repo.heads()
        # heads = repo.heads()
        openheads = [h for h in heads if not self.repo[h].extra().get('close', False)]
        branchheads = {}
        for head in openheads:
            ctx = self.repo[head]
            branch = ctx.branch()
            if branch not in branchheads:
                branchheads[branch] = []
            branchheads[branch].append(ctx)

        for branch, heads in list(branchheads.items()):
            self.merge_heads(branch, heads, request.id)

        for bundle in bundles:
            self.ui.status(str.encode("Deleting local bundle: %s\n" % bundle))
            os.unlink(bundle)

        return True

    def jira_section_available(self):
        if self.ui.config(b'jira', b'server', None) is None:
            self.ui.status(str.encode("You don't have a server specified in [jira] section in your  ~/.hgrc.\n"))
            return False
        if self.ui.config(b'jira', b'user', None) is None:
            self.ui.status(str.encode("You don't have a user specified in [jira] section in your  ~/.hgrc.\n"))
            return False
        if self.ui.config(b'jira', b'password', None) is None:
            self.ui.status(str.encode("You don't have a password specified in [jira] section in your  ~/.hgrc.\n"))
            return False
        return True

    def update_jira(self, request, message=None):
        if self.jira_section_available() is False:
            return
        review_board_message = "Review request submitted."
        jira_tickets = re.findall(r'([A-Z]+-[0-9]+)', request.summary)
        jira_tickets = list(set(jira_tickets))
        jira_server = self.ui.config(b'jira', b'server')
        jira_user = self.ui.config(b'jira', b'user')
        jira_password = self.ui.config(b'jira', b'password')

        # Get Submitter info from review
        review = self.reviewboard._get_request(request.id)
        submitter_name = review['links']['submitter']['title']
        submitter_href = review['links']['submitter']['href']

        reviewboard_server = self.ui.config(b'reviewboard', b'server')
        review_url = reviewboard_server.decode('utf8') + "/r/" + str(request.id)
        jira_comment = "Review Board: " + message + "!\n" + "User: [~" + submitter_name + "]\n" + "Link: " + review_url

        for jira_ticket in jira_tickets:
            self.ui.status(str.encode("Jira ticket: %s\n" % jira_ticket))
            self.ui.status(str.encode("Adding comment for ticket...\n"))
            url = jira_server + b'/rest/api/latest/issue/%s/comment' % jira_ticket
            auth = base64.encodestring('%s:%s' % (jira_user, jira_password)).replace('\n', '')

            data = json.dumps({'body': jira_comment})

            request = urllib.request.Request(url, data, {
                'Authorization': 'Basic %s' % auth,
                'X-Atlassian-Token': 'no-check',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })

            try:
                response = urllib.request.urlopen(request).read()
            except IOError as e:
                if hasattr(e, 'code') and e.code == 404:
                    self.ui.status(str.encode("Jira ticket: %s" % jira_ticket + " does not exist!\n"))
                else:
                    self.ui.status(str.encode("Jira error: " + str(e)))
            else:
                self.ui.status(str.encode("Comment added.\n"))

    def merge_heads(self, branch, heads, requestid):
        if len(heads) == 1:
            return  # nothing to merge

        if len(heads) > 2:
            self.ui.status(str.encode("Review request bundle import resulted in more than two heads on branch %s" % branch))
            raise util.error.Abort(str.encode("Review request bundle import resulted in more than two heads on branch "
                                              "%s" % branch))

        self.ui.status(str.encode("Merging heads for branch %s\n") % branch)
        self.ui.pushbuffer()
        try:
            commands.update(self.ui, self.repo, heads[0].rev())
            commands.merge(self.ui, self.repo, tool=b'internal:fail')

            message = str.encode("Automatic merge after review request %s fetch" % requestid)
            commands.commit(self.ui, self.repo, message=message)
        finally:
            self.ui.popbuffer()

    def report_success(self, request):
        from . import BUNDLE_ATTACHMENT_CAPTION
        self.push_reviewed()
        self.reviewboard.rename_attachments_with_caption(request.id,
                                                         BUNDLE_ATTACHMENT_CAPTION,
                                                         str.encode("%s (submitted)" % BUNDLE_ATTACHMENT_CAPTION))
        try:
            # ReviewBoard has serialization issue with attachments when webhook is active, so publish succeeds but throws error.
            # Related ticket: https://hellosplat.com/s/beanbag/tickets/4542/
            self.reviewboard.publish(request.id)
        except ReviewBoardError:
            pass
        self.ui.status(str.encode("Submitting review request %s\n" % request.id))
        self.reviewboard.submit(request.id)

    def push_reviewed(self):
        push_result = commands.push(self.ui, self.repo, self.rbrepo.path.encode(), new_branch=True)
        self.ui.status(str.encode("Push result %d\n" % push_result))
        if push_result != 0:
            if push_result == 1:
                self.ui.status(str.encode("Nothing to push. Push command returned: %d\n" % push_result))
            else:
                self.ui.status(
                    str.encode("Cannot push. Please resubmit review request. Push command returned: %d\n" % push_result))
                raise util.error.Abort("Cannot push. Please resubmit review request. Push command returned: %d" % push_result)

    def report_failure(self, request, exception):
        self.ui.status(str.encode("Reporting failure to review request %s\n" % request.id))
        from . import BUNDLE_ATTACHMENT_CAPTION
        reviewmsg = str.encode("Automatic process was unable to add reviewed changesets into "
                      "the mercurial repository: \n\n    %s.\n\nResolve the problem "
                      "and resubmit review." % exception.message)
        self.reviewboard.rename_attachments_with_caption(request.id,
                                                         BUNDLE_ATTACHMENT_CAPTION,
                                                         str.encode("%s (failed)" % BUNDLE_ATTACHMENT_CAPTION))
        try:
            # ReviewBoard has serialization issue with attachments when webhook is active, so publish succeeds but throws error.
            # Related ticket: https://hellosplat.com/s/beanbag/tickets/4542/
            self.reviewboard.publish(request.id)
        except ReviewBoardError:
            pass
        self.reviewboard.review(request.id, reviewmsg)

    def clean_working_copy(self):
        self.strip_outgoing()

        self.ui.pushbuffer()
        try:
            commands.update(self.ui, self.repo, clean=True)
            commands.revert(self.ui, self.repo, all=True, no_backup=True)
        finally:
            self.ui.popbuffer()

    def strip_outgoing(self):
        from . import findoutgoing
        remoterepo = hg.peer(self.repo, self.opts, str.encode(self.rbrepo.path))

        out = findoutgoing(self.repo, remoterepo)
        if not out:
            return

        cl = self.repo.changelog
        revs = set([cl.rev(r) for r in out])
        
        if HgVersion(util.version().decode()) >= HgVersion('2.3'):
            descendants = set(cl.descendants(revs))
        else:
            descendants = set(cl.descendants(*revs))

        roots = revs.difference(descendants)


        roots = list(roots)
        roots.sort()
        roots.reverse()
        
        string_list = [str(item) for item in roots]
        rootstr='Stripping local revisions '+ ' '.join(string_list)

        self.ui.status(rootstr.encode())

        for node in roots:
            tmpbstr="Stripping revision %s..." + str(node)+"\n"
            self.ui.note(tmpbstr.encode())
            self.ui.pushbuffer()
            try:
                repair.strip(self.ui, self.repo, cl.node(node), backup='none')
            finally:
                self.ui.popbuffer()

from mercurial import util
from mock import patch
from nose.tools import eq_

from mercurial_reviewboard import postreview
from mercurial_reviewboard.tests import get_initial_opts, get_repo, mock_ui


@patch('mercurial_reviewboard.send_review')
def test_outgoing(mock_send):
    ui = mock_ui()
    repo = get_repo(ui, 'two_revs')
    opts = get_initial_opts()
    opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/no_revs'
    opts['outgoingchanges'] = True
    opts['outgoing'] = False
    postreview(ui, repo, **opts)

    expected = open('mercurial_reviewboard/tests/diffs/outgoing', 'r').read()
    eq_(expected, mock_send.call_args[0][4])


@patch('mercurial_reviewboard.send_review')
def test_outgoing_one_rev(mock_send):
    ui = mock_ui()
    repo = get_repo(ui, 'one_rev')
    opts = get_initial_opts()
    opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/no_revs'
    opts['outgoingchanges'] = True
    opts['outgoing'] = False
    postreview(ui, repo, **opts)

    expected = open('mercurial_reviewboard/tests/diffs/outgoing_one_rev',
                    'r').read()
    eq_(expected, mock_send.call_args[0][4])


@patch('mercurial_reviewboard.send_review')
def test_outgoing_one_rev_no_outgoing_flag(mock_send):
    try:
        ui = mock_ui()
        repo = get_repo(ui, 'one_rev')
        opts = get_initial_opts()
        opts['outgoingchanges'] = True
        opts['outgoing'] = False
        postreview(ui, repo, **opts)

        expected = open('mercurial_reviewboard/tests/diffs/outgoing_one_rev',
                        'r').read()
        eq_(expected, mock_send.call_args[0][4])
    except util.error.Abort as e:
        expected = ("When using the -g/--outgoingchanges flag, you must "
                    "also use either the -o or the -O <repo> flag.")
        eq_(expected, e.__str__())


@patch('mercurial_reviewboard.send_review')
def test_outgoing_with_branch(mock_send):
    '''Test that only one change is included, despite a commit to another 
    branch.'''
    ui = mock_ui()
    repo = get_repo(ui, 'two_revs_clone')
    opts = get_initial_opts()
    opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/two_revs'
    opts['outgoingchanges'] = True
    opts['outgoing'] = False
    postreview(ui, repo, '2', **opts)

    expected = open('mercurial_reviewboard/tests/diffs/outgoing_with_branch',
                    'r').read()
    eq_(expected, mock_send.call_args[0][4])


@patch('mercurial_reviewboard.send_review')
def test_no_outgoing_no_revs(mock_send):
    try:
        ui = mock_ui()
        repo = get_repo(ui, 'no_revs')
        opts = get_initial_opts()
        opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/no_revs'
        opts['outgoingchanges'] = True
        postreview(ui, repo, **opts)
        assert 0, "Should have raised an Abort."
    except util.error.Abort as e:
        check_parent_rev_exception(e)


@patch('mercurial_reviewboard.send_review')
def test_no_outgoing_two_revs(mock_send):
    try:
        ui = mock_ui()
        repo = get_repo(ui, 'two_revs')
        opts = get_initial_opts()
        opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/two_revs'
        opts['outgoingchanges'] = True
        postreview(ui, repo, **opts)
        assert 0, "Should have raised an Abort."
    except util.error.Abort as e:
        check_parent_rev_exception(e)


def check_parent_rev_exception(e):
    eq_("Unable to determine parent revision for diff. "
        "If using -g/--outgoingchanges, make sure you have some "
        "(type 'hg out'). Did you forget to commit ('hg st')?",
        e.__str__()
        )

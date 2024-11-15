from mock import patch
from nose.tools import eq_

from mercurial_reviewboard import postreview
from mercurial_reviewboard.tests import get_initial_opts, get_repo, mock_ui


@patch('mercurial_reviewboard.send_review')
def test_diff(mock_send):
    ui = mock_ui()

    repo = get_repo(ui, 'two_revs')
    opts = get_initial_opts()
    opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/no_revs'
    opts['outgoingchanges'] = False
    opts['outgoing'] = False

    postreview(ui, repo, **opts)

    expected = open('mercurial_reviewboard/tests/diffs/two_revs_1',
                    'r').read()
    eq_(expected, mock_send.call_args[0][4])


@patch('mercurial_reviewboard.send_review')
def test_parentdiff(mock_send):
    ui = mock_ui()

    repo = get_repo(ui, 'two_revs')
    opts = get_initial_opts()
    opts['outgoingrepo'] = b'mercurial_reviewboard/tests/repos/no_revs'
    opts['outgoingchanges'] = False
    opts['outgoing'] = False

    postreview(ui, repo, **opts)

    expected = open('mercurial_reviewboard/tests/diffs/two_revs_0',
                    'r').read()
    eq_(expected, mock_send.call_args[0][5])

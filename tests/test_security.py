import sqlite3

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

import main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database = tmp_path / 'test.db'
    monkeypatch.setattr(main, 'DATABASE_PATH', str(database))
    main.app.config.update(TESTING=True, SECRET_KEY='test-secret', SESSION_COOKIE_SECURE=False)
    main.ACTIVE_SESSIONS.clear()
    main.failed_attempts.clear()
    main.init_db()
    return main.app.test_client()


def create_user(username, password, role='viewer', hashed=True):
    stored_password = generate_password_hash(password) if hashed else password
    conn = sqlite3.connect(main.DATABASE_PATH)
    conn.execute(
        'INSERT INTO users (username, password, role, must_change_password) VALUES (?, ?, ?, 0)',
        (username, stored_password, role),
    )
    conn.commit()
    conn.close()


def csrf_token(client):
    client.get('/login')
    with client.session_transaction() as session:
        return session['_csrf_token']


def login(client, username, password, next_url=None):
    target = '/login' if next_url is None else f'/login?next={next_url}'
    return client.post(
        target,
        data={'username': username, 'password': password, '_csrf_token': csrf_token(client)},
    )


def authenticated_session(client, username, role):
    conn = sqlite3.connect(main.DATABASE_PATH)
    conn.execute('UPDATE users SET must_change_password = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    session_id = f'{username}-session'
    main.ACTIVE_SESSIONS[session_id] = {'username': username}
    with client.session_transaction() as session:
        session.update(
            logged_in=True,
            username=username,
            user_role=role,
            session_id=session_id,
            last_activity='2099-01-01T00:00:00',
            _csrf_token='csrf-test-token',
        )


def test_login_requires_csrf(client):
    response = client.post('/login', data={'username': 'nobody', 'password': 'bad'})
    assert response.status_code == 302
    assert response.headers['Location'] == '/login'

    follow_up = client.get('/login')
    assert b'Your session expired after an application update.' in follow_up.data


def test_legacy_plaintext_password_is_migrated(client):
    create_user('legacy', 'ValidLegacy2026!', hashed=False)
    response = login(client, 'legacy', 'ValidLegacy2026!')
    assert response.status_code == 302

    conn = sqlite3.connect(main.DATABASE_PATH)
    stored = conn.execute("SELECT password FROM users WHERE username = 'legacy'").fetchone()[0]
    conn.close()
    assert stored != 'ValidLegacy2026!'
    assert check_password_hash(stored, 'ValidLegacy2026!')


def test_external_next_url_is_rejected(client):
    create_user('user', 'ValidUser2026!')
    response = login(client, 'user', 'ValidUser2026!', 'https://attacker.example/path')
    assert response.headers['Location'] == '/'


def test_viewer_cannot_modify_findings(client):
    create_user('viewer', 'ValidViewer2026!', 'viewer')
    authenticated_session(client, 'viewer', 'viewer')
    assert client.get('/add').status_code == 403
    assert client.post('/delete/1', data={'_csrf_token': 'csrf-test-token'}).status_code == 403


def test_editor_can_add_but_cannot_delete(client):
    create_user('editor', 'ValidEditor2026!', 'editor')
    authenticated_session(client, 'editor', 'editor')
    assert client.get('/add').status_code == 200
    assert client.post('/delete/1', data={'_csrf_token': 'csrf-test-token'}).status_code == 403


def test_admin_delete_requires_post_and_csrf(client):
    authenticated_session(client, 'admin', 'admin')
    assert client.get('/delete/1').status_code == 405
    assert client.post('/delete/1').status_code == 400
    assert client.post('/delete/1', data={'_csrf_token': 'csrf-test-token'}).status_code == 302


def test_theme_assets_and_toggle_are_available(client):
    login_page = client.get('/login')
    assert login_page.status_code == 200
    assert b'/static/js/theme.js' in login_page.data
    assert b'/static/css/style.css' in login_page.data
    assert client.get('/static/js/theme.js').status_code == 200
    stylesheet = client.get('/static/css/style.css')
    assert b'.hidden { display: none !important; }' not in stylesheet.data

    authenticated_session(client, 'admin', 'admin')
    dashboard = client.get('/')
    assert dashboard.status_code == 200
    assert b'data-theme-toggle' in dashboard.data


def test_only_superadmin_can_manage_users(client):
    create_user('manager', 'ValidManager2026!', 'admin')
    authenticated_session(client, 'manager', 'admin')
    assert client.get('/admin/users').status_code == 403

    authenticated_session(client, 'admin', 'superadmin')
    page = client.get('/admin/users')
    assert page.status_code == 200
    assert b'User Management' in page.data


def test_superadmin_can_send_alert_and_delete_user(client):
    create_user('recipient', 'ValidRecipient2026!', 'viewer')
    authenticated_session(client, 'admin', 'superadmin')
    response = client.post(
        '/admin/users/recipient/alert',
        data={'_csrf_token': 'csrf-test-token', 'message': 'Please review your assigned finding.'},
    )
    assert response.status_code == 302

    authenticated_session(client, 'recipient', 'viewer')
    dashboard = client.get('/')
    assert b'Please review your assigned finding.' in dashboard.data
    assert b'Alert from admin' in dashboard.data

    authenticated_session(client, 'admin', 'superadmin')
    response = client.post(
        '/admin/users/recipient/delete', data={'_csrf_token': 'csrf-test-token'}
    )
    assert response.status_code == 302
    assert main.get_user_from_db('recipient') is None

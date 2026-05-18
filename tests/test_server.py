import io
import os
import sqlite3
import tempfile
import unittest

import server


class WashDogServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        self.old_upload_dir = server.UPLOAD_DIR
        self.old_import_dir = server.IMPORT_DIR
        server.DB = os.path.join(self.tmp.name, 'washdog.db')
        server.UPLOAD_DIR = os.path.join(self.tmp.name, 'uploads')
        server.IMPORT_DIR = os.path.join(self.tmp.name, 'imports')
        os.makedirs(server.UPLOAD_DIR, exist_ok=True)
        os.makedirs(server.IMPORT_DIR, exist_ok=True)
        server.init()

    def tearDown(self):
        server.DB = self.old_db
        server.UPLOAD_DIR = self.old_upload_dir
        server.IMPORT_DIR = self.old_import_dir
        self.tmp.cleanup()

    def start_response(self):
        captured = {}

        def _start_response(status, headers):
            captured['status'] = status
            captured['headers'] = headers

        return captured, _start_response

    def post_environ(self, path, payload, cookie=''):
        body = payload.encode()
        return {
            'REQUEST_METHOD': 'POST',
            'PATH_INFO': path,
            'CONTENT_LENGTH': str(len(body)),
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'HTTP_COOKIE': cookie,
            'wsgi.input': io.BytesIO(body),
        }

    def get_environ(self, path, cookie=''):
        return {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': path,
            'CONTENT_LENGTH': '0',
            'HTTP_COOKIE': cookie,
            'wsgi.input': io.BytesIO(b''),
        }

    def test_init_creates_pbkdf2_admin_password(self):
        con = server.db()
        admin = con.execute("SELECT * FROM users WHERE email='admin@washdog.local'").fetchone()
        con.close()

        self.assertIsNotNone(admin)
        self.assertTrue(admin['password'].startswith('pbkdf2_sha256$'))
        self.assertTrue(server.verify_pw('admin123', admin['password']))

    def test_login_sets_signed_http_only_same_site_cookie(self):
        captured, start_response = self.start_response()
        response = server.login(
            self.post_environ('/login', 'email=admin%40washdog.local&password=admin123'),
            start_response,
            None,
        )

        self.assertEqual(response, [b''])
        self.assertEqual(captured['status'], '302 Found')
        headers = dict(captured['headers'])
        self.assertEqual(headers['Location'], '/admin/templates')
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Lax', headers['Set-Cookie'])
        user = server.current_user(self.get_environ('/', headers['Set-Cookie']))
        self.assertEqual(user['email'], 'admin@washdog.local')

    def test_legacy_password_is_accepted_and_upgraded_on_login(self):
        con = server.db()
        con.execute(
            "UPDATE users SET password=? WHERE email='admin@washdog.local'",
            (server.legacy_hash_pw('admin123'),),
        )
        con.commit()
        con.close()

        captured, start_response = self.start_response()
        server.login(
            self.post_environ('/login', 'email=admin%40washdog.local&password=admin123'),
            start_response,
            None,
        )

        self.assertEqual(captured['status'], '302 Found')
        con = server.db()
        upgraded = con.execute("SELECT password FROM users WHERE email='admin@washdog.local'").fetchone()['password']
        con.close()
        self.assertTrue(upgraded.startswith('pbkdf2_sha256$'))
        self.assertTrue(server.verify_pw('admin123', upgraded))

    def test_uploaded_file_path_rejects_traversal(self):
        self.assertIsNone(server.uploaded_file_path('/uploads/../server.py'))
        self.assertEqual(
            server.uploaded_file_path('/uploads/logo.png'),
            os.path.normpath(os.path.join(server.UPLOAD_DIR, 'logo.png')),
        )

    def test_save_upload_sanitizes_file_names(self):
        saved = server.save_upload(
            {'filename': '../my logo!.png', 'content': b'img'},
            server.UPLOAD_DIR,
            'logo_',
        )

        self.assertTrue(saved.startswith(server.UPLOAD_DIR))
        self.assertTrue(os.path.exists(saved))
        self.assertNotIn('..', os.path.basename(saved))
        self.assertTrue(os.path.basename(saved).endswith('my_logo_.png'))

    def test_invalid_database_import_is_reported_without_exception(self):
        message = server.handle_db_action(
            'db_import',
            {'database_file': {'filename': 'not-a-db.sqlite', 'content': b'not sqlite'}},
        )

        self.assertIn('Import refusé', message)

    def test_app_does_not_serve_files_outside_upload_directory(self):
        captured, start_response = self.start_response()
        response = server.app(self.get_environ('/uploads/../server.py'), start_response)

        self.assertEqual(captured['status'], '404 Not Found')
        self.assertEqual(response, [b'Not found'])


if __name__ == '__main__':
    unittest.main()

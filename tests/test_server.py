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
        self.old_cloud_backup_root = server.CLOUD_BACKUP_ROOT
        server.DB = os.path.join(self.tmp.name, 'washdog.db')
        server.UPLOAD_DIR = os.path.join(self.tmp.name, 'uploads')
        server.IMPORT_DIR = os.path.join(self.tmp.name, 'imports')
        server.CLOUD_BACKUP_ROOT = os.path.join(self.tmp.name, 'cloud_backups')
        os.makedirs(server.UPLOAD_DIR, exist_ok=True)
        os.makedirs(server.IMPORT_DIR, exist_ok=True)
        os.makedirs(server.CLOUD_BACKUP_ROOT, exist_ok=True)
        server.init()

    def tearDown(self):
        server.DB = self.old_db
        server.UPLOAD_DIR = self.old_upload_dir
        server.IMPORT_DIR = self.old_import_dir
        server.CLOUD_BACKUP_ROOT = self.old_cloud_backup_root
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


    def test_init_adds_dog_dashboard_columns(self):
        con = server.db()
        columns = {row['name'] for row in con.execute('PRAGMA table_info(dogs)').fetchall()}
        con.close()

        self.assertIn('age', columns)
        self.assertIn('registered_at', columns)

    def test_dashboard_admin_sees_all_shops_and_metrics(self):
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(1,'Centre','Rue A')")
        con.execute("INSERT INTO shops(id,name,address) VALUES(2,'Sud','Rue B')")
        con.execute(
            "INSERT INTO users(id,name,email,password,role,registered_at) VALUES(10,'Manager','m@example.test',?,'manager','2026-01-01')",
            (server.hash_pw('pw'),),
        )
        con.execute('INSERT INTO manager_shops(manager_id,shop_id) VALUES(10,1)')
        con.execute(
            "INSERT INTO users(id,name,email,password,role,shop_id,birth_date,registered_at) VALUES(20,'Client','c@example.test',?,'client',1,'1990-01-01','2026-01-02')",
            (server.hash_pw('pw'),),
        )
        con.execute(
            "INSERT INTO dogs(client_id,name,breed,age,registered_at) VALUES(20,'Rex','Labrador',4,'2026-01-03')"
        )
        con.execute(
            "INSERT INTO shop_services(shop_id,name,category,active) VALUES(1,'Lavage','Prestations de base',1)"
        )
        con.commit()
        admin = con.execute("SELECT * FROM users WHERE role='admin'").fetchone()
        con.close()

        captured, start_response = self.start_response()
        response = server.admin_dashboard(self.get_environ('/admin/dashboard'), start_response, admin)
        html = b''.join(response).decode()

        self.assertEqual(captured['status'], '200 OK')
        self.assertIn('Centre', html)
        self.assertIn('Sud', html)
        self.assertIn('Clients par tranche d’âge', html)
        self.assertIn('Labrador', html)
        self.assertIn('Prestations de base', html)
        self.assertIn('Graphiques camembert', html)
        self.assertIn('Graphiques en courbe', html)
        self.assertIn('line-mode', html)
        self.assertIn('Managers par boutique', html)

    def test_dashboard_manager_is_limited_to_reference_shops(self):
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(1,'Centre','Rue A')")
        con.execute("INSERT INTO shops(id,name,address) VALUES(2,'Sud','Rue B')")
        con.execute(
            "INSERT INTO users(id,name,email,password,role,registered_at) VALUES(10,'Manager','m@example.test',?,'manager','2026-01-01')",
            (server.hash_pw('pw'),),
        )
        con.execute('INSERT INTO manager_shops(manager_id,shop_id) VALUES(10,2)')
        con.commit()
        manager = con.execute("SELECT * FROM users WHERE id=10").fetchone()
        con.close()

        captured, start_response = self.start_response()
        response = server.admin_dashboard(self.get_environ('/admin/dashboard'), start_response, manager)
        html = b''.join(response).decode()

        self.assertEqual(captured['status'], '200 OK')
        self.assertNotIn('Centre', html)
        self.assertIn('Sud', html)
        self.assertIn('Manager : vue filtrée', html)

    def test_admin_dogs_manager_sees_only_reference_shop_dogs(self):
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(1,'Centre','Rue A')")
        con.execute("INSERT INTO shops(id,name,address) VALUES(2,'Sud','Rue B')")
        con.execute(
            "INSERT INTO users(id,name,email,password,role,registered_at) VALUES(10,'Manager','m@example.test',?,'manager','2026-01-01')",
            (server.hash_pw('pw'),),
        )
        con.execute('INSERT INTO manager_shops(manager_id,shop_id) VALUES(10,2)')
        con.execute(
            "INSERT INTO users(id,name,email,password,role,shop_id,registered_at) VALUES(20,'Client Centre','c1@example.test',?,'client',1,'2026-01-02')",
            (server.hash_pw('pw'),),
        )
        con.execute(
            "INSERT INTO users(id,name,email,password,role,shop_id,registered_at) VALUES(21,'Client Sud','c2@example.test',?,'client',2,'2026-01-02')",
            (server.hash_pw('pw'),),
        )
        con.execute("INSERT INTO dogs(client_id,name,breed,age,registered_at) VALUES(20,'Rex','Labrador',4,'2026-01-03')")
        con.execute("INSERT INTO dogs(client_id,name,breed,age,registered_at) VALUES(21,'Nina','Caniche',6,'2026-01-03')")
        con.commit()
        manager = con.execute("SELECT * FROM users WHERE id=10").fetchone()
        con.close()

        captured, start_response = self.start_response()
        response = server.admin_dogs(self.get_environ('/admin/dogs'), start_response, manager)
        html = b''.join(response).decode()

        self.assertEqual(captured['status'], '200 OK')
        self.assertIn('Manager : accès limité', html)
        self.assertIn('Nina', html)
        self.assertIn('Client Sud', html)
        self.assertNotIn('Rex', html)
        self.assertNotIn('Client Centre', html)

    def test_admin_dogs_client_sees_only_owned_dogs(self):
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(1,'Centre','Rue A')")
        con.execute(
            "INSERT INTO users(id,name,email,password,role,shop_id,registered_at) VALUES(20,'Client Owner','owner@example.test',?,'client',1,'2026-01-02')",
            (server.hash_pw('pw'),),
        )
        con.execute(
            "INSERT INTO users(id,name,email,password,role,shop_id,registered_at) VALUES(21,'Client Other','other@example.test',?,'client',1,'2026-01-02')",
            (server.hash_pw('pw'),),
        )
        con.execute("INSERT INTO dogs(client_id,name,breed,age,registered_at) VALUES(20,'Nina','Caniche',6,'2026-01-03')")
        con.execute("INSERT INTO dogs(client_id,name,breed,age,registered_at) VALUES(21,'Rex','Labrador',4,'2026-01-03')")
        con.commit()
        client = con.execute("SELECT * FROM users WHERE id=20").fetchone()
        con.close()

        captured, start_response = self.start_response()
        response = server.admin_dogs(self.get_environ('/admin/dogs'), start_response, client)
        html = b''.join(response).decode()

        self.assertEqual(captured['status'], '200 OK')
        self.assertIn('Client : accès limité', html)
        self.assertIn('Nina', html)
        self.assertIn('Client Owner', html)
        self.assertNotIn('Rex', html)
        self.assertNotIn('Client Other', html)

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
        self.assertEqual(headers['Location'], '/admin/dashboard')
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


    def test_cloud_full_backup_and_restore_from_google_drive(self):
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(7,'Cloud Shop','Rue Cloud')")
        con.commit()
        con.close()

        message = server.handle_db_action(
            'db_cloud_backup',
            {'cloud_provider': 'google_drive', 'backup_mode': 'full'},
        )

        self.assertIn('Sauvegarde complète cloud créée sur Google Drive', message)
        backups = server.list_cloud_backups('google_drive')
        full_backup = next(item for item in backups if item['name'].endswith('.db'))

        con = server.db()
        con.execute("DELETE FROM shops WHERE id=7")
        con.commit()
        con.close()

        restore_message = server.handle_db_action(
            'db_cloud_restore',
            {'cloud_provider': 'google_drive', 'backup_file': full_backup['name']},
        )

        self.assertIn('Base de données restaurée depuis Google Drive', restore_message)
        con = server.db()
        restored = con.execute('SELECT name FROM shops WHERE id=7').fetchone()
        con.close()
        self.assertEqual(restored['name'], 'Cloud Shop')

    def test_cloud_incremental_backup_and_restore_from_proton_drive(self):
        server.handle_db_action(
            'db_cloud_backup',
            {'cloud_provider': 'proton_drive', 'backup_mode': 'full'},
        )
        con = server.db()
        con.execute("INSERT INTO shops(id,name,address) VALUES(8,'Incremental Shop','Rue Proton')")
        con.commit()
        con.close()

        message = server.handle_db_action(
            'db_cloud_backup',
            {'cloud_provider': 'proton_drive', 'backup_mode': 'incremental'},
        )

        self.assertIn('Sauvegarde incrémentielle cloud créée sur Proton Drive', message)
        incremental = next(item for item in server.list_cloud_backups('proton_drive') if item['name'].endswith('.json'))

        con = server.db()
        con.execute("DELETE FROM shops WHERE id=8")
        con.commit()
        con.close()

        restore_message = server.handle_db_action(
            'db_cloud_restore',
            {'cloud_provider': 'proton_drive', 'backup_file': incremental['name']},
        )

        self.assertIn('backup incrémentiel Proton Drive', restore_message)
        con = server.db()
        restored = con.execute('SELECT name FROM shops WHERE id=8').fetchone()
        con.close()
        self.assertEqual(restored['name'], 'Incremental Shop')

    def test_database_page_contains_cloud_backup_controls(self):
        html = server.database_forms('/admin/database')

        self.assertIn('Sauvegarde cloud', html)
        self.assertIn('Google Drive', html)
        self.assertIn('Proton Drive', html)
        self.assertIn('Backup complet', html)
        self.assertIn('Backup incrémentiel', html)
        self.assertIn('Restauration cloud', html)

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

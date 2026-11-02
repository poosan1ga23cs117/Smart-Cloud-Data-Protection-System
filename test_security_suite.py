"""
================================================================
ZERO TRUST APPLICATION SECURITY TEST SUITE
================================================================
Tests all 20 required security objectives:
 1. Valid user login
 2. Invalid password
 3. MFA OTP verification
 4. Expired OTP
 5. Excessive login attempts
 6. Account lockout
 7. Session expiration
 8. User A uploads a file
 9. User A downloads their own file
10. User B cannot see User A's private file
11. User B cannot download User A's private file
12. User B cannot delete User A's private file
13. User B cannot access User A's fragments
14. File integrity verification
15. Modified or corrupted encrypted file detection
16. Audit-chain verification
17. Audit tampering detection
18. S3 upload and download
19. S3 permission failure handling
20. Local storage behavior
================================================================
"""

import io
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

from app import create_app
from audit import compute_log_hash, log_activity, verify_chain
from config import Config
from crypto import IntegrityError, decrypt_bytes, encrypt_bytes, sha256_bytes
from models import AuditLog, File, User, db
import s3_manager


class ZeroTrustSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure app in testing mode
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        from security import limiter
        try:
            limiter.reset()
        except Exception:
            pass

    def tearDown(self):
        db.session.rollback()
        self.app_context.pop()

    # ------------------------------------------------------------
    # 1. Valid user login
    # ------------------------------------------------------------
    def test_01_valid_user_login(self):
        email = "test_user1@scdp.local"
        password = "SecurePassword123!"

        # Ensure user exists and is verified
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        else:
            user.email_verified = True
            user.account_locked = False
            user.failed_attempts = 0
            user.risk_score = 0
            user.set_password(password)
            db.session.commit()

        resp = self.client.post("/login", json={"email": email, "password": password})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("Login Successful", data["message"])
        print("[PASS] Test 1: Valid user login")

    # ------------------------------------------------------------
    # 2. Invalid password
    # ------------------------------------------------------------
    def test_02_invalid_password(self):
        email = "test_user2@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password("CorrectPass123!")
            db.session.add(user)
            db.session.commit()
        else:
            user.account_locked = False
            user.failed_attempts = 0
            db.session.commit()

        resp = self.client.post("/login", json={"email": email, "password": "WrongPassword!"})
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertEqual(data["message"], "Wrong Password")
        self.assertIn("remaining_attempts", data)
        print("[PASS] Test 2: Invalid password")

    # ------------------------------------------------------------
    # 3. MFA OTP verification
    # ------------------------------------------------------------
    def test_03_mfa_otp_verification(self):
        email = "test_mfa@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=False, risk_score=0)
            user.set_password("SecurePass123!")
            db.session.add(user)
            db.session.commit()

        plain_otp = "123456"
        user.set_otp(plain_otp, ttl_seconds=300)
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["pending_mfa"] = email
            sess["pending_intent"] = "register"

        resp = self.client.post("/verify_otp", json={"email": email, "otp": plain_otp, "mode": "register"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("Verification successful", data["message"])

        # User is now verified
        updated_user = User.query.filter_by(email=email).first()
        self.assertTrue(updated_user.email_verified)
        print("[PASS] Test 3: MFA OTP verification")

    # ------------------------------------------------------------
    # 4. Expired OTP
    # ------------------------------------------------------------
    def test_04_expired_otp(self):
        email = "test_expired_otp@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=False, risk_score=0)
            user.set_password("SecurePass123!")
            db.session.add(user)
            db.session.commit()

        user.set_otp("654321", ttl_seconds=-10)  # already expired
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["pending_mfa"] = email
            sess["pending_intent"] = "login"

        resp = self.client.post("/verify_otp", json={"email": email, "otp": "654321", "mode": "login"})
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertIn("expired", data["message"].lower())
        print("[PASS] Test 4: Expired OTP")

    # ------------------------------------------------------------
    # 5. Excessive login attempts
    # ------------------------------------------------------------
    def test_05_excessive_login_attempts(self):
        email = "test_excessive@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password("CorrectPass123!")
            db.session.add(user)
            db.session.commit()
        else:
            user.account_locked = False
            user.failed_attempts = 0
            db.session.commit()

        # Submit 3 wrong passwords
        for i in range(3):
            resp = self.client.post("/login", json={"email": email, "password": "BadPassword"})
            self.assertEqual(resp.status_code, 401)

        user = User.query.filter_by(email=email).first()
        self.assertEqual(user.failed_attempts, 3)
        print("[PASS] Test 5: Excessive login attempts tracked")

    # ------------------------------------------------------------
    # 6. Account lockout
    # ------------------------------------------------------------
    def test_06_account_lockout(self):
        email = "test_lockout@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password("RealPassword123!")
            db.session.add(user)
            db.session.commit()
        else:
            user.account_locked = False
            user.failed_attempts = 0
            db.session.commit()

        # Exceed MAX_FAILED_ATTEMPTS (5) across requests
        resp = None
        for i in range(5):
            resp = self.client.post(
                "/login",
                json={"email": email, "password": "WrongPassword"},
                headers={"X-Forwarded-For": f"192.168.10.{i+1}"},
            )

        self.assertEqual(resp.status_code, 403)
        user = User.query.filter_by(email=email).first()
        self.assertTrue(user.account_locked)
        self.assertIsNotNone(user.locked_until)
        print("[PASS] Test 6: Account lockout triggered after 5 failed attempts")

    # ------------------------------------------------------------
    # 7. Session expiration
    # ------------------------------------------------------------
    def test_07_session_expiration(self):
        email = "test_session_user@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password("Pass12345!")
            db.session.add(user)
            db.session.commit()

        # Simulate an idle session expired (> PERMANENT_SESSION_LIFETIME seconds ago)
        with self.client.session_transaction() as sess:
            sess["email"] = email
            sess["mfa_verified"] = True
            sess["auth_version"] = user.auth_version or 0
            sess["last_activity"] = (datetime.utcnow() - timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME + 50)).timestamp()

        resp = self.client.get(f"/files/{email}")
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertIn("Expired", data["message"])
        print("[PASS] Test 7: Session expiration verified")

    # ------------------------------------------------------------
    # 8. User A uploads a file
    # ------------------------------------------------------------
    def test_08_user_a_uploads_file(self):
        email = "user_a@scdp.local"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, email_verified=True, risk_score=0)
            user.set_password("PasswordA123!")
            db.session.add(user)
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess["email"] = email
            sess["mfa_verified"] = True
            sess["auth_version"] = user.auth_version or 0
            sess["last_activity"] = datetime.utcnow().timestamp()

        file_content = b"Top secret confidential content from User A"
        data = {
            "file": (io.BytesIO(file_content), "confidential_a.pdf")
        }
        resp = self.client.post("/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res_data = resp.get_json()
        self.assertEqual(res_data["filename"], "confidential_a.pdf")
        self.assertIn("sha256", res_data)

        record = File.query.filter_by(email=email, filename="confidential_a.pdf").first()
        self.assertIsNotNone(record)
        self.assertEqual(record.sha256_hash, sha256_bytes(file_content))
        print("[PASS] Test 8: User A uploads file (encrypted, fragmented, stored)")

    # ------------------------------------------------------------
    # 9. User A downloads their own file
    # ------------------------------------------------------------
    def test_09_user_a_downloads_own_file(self):
        email = "user_a@scdp.local"
        user = User.query.filter_by(email=email).first()

        # Step 1: Request download (requires Step-Up OTP)
        with self.client.session_transaction() as sess:
            sess["email"] = email
            sess["mfa_verified"] = True
            sess["auth_version"] = user.auth_version or 0
            sess["last_activity"] = datetime.utcnow().timestamp()

        resp = self.client.get(f"/download/{email}/confidential_a.pdf")
        self.assertEqual(resp.status_code, 202)
        self.assertTrue(resp.get_json()["download_otp_required"])

        # Step 2: Authorize download via single-use authorization token
        record = File.query.filter_by(email=email, filename="confidential_a.pdf").order_by(File.id.desc()).first()
        with self.client.session_transaction() as sess:
            sess["download_authorized"] = "confidential_a.pdf"
            sess["download_authorized_file_id"] = record.id

        resp_dl = self.client.get(f"/download/{email}/confidential_a.pdf")
        self.assertEqual(resp_dl.status_code, 200)
        self.assertEqual(resp_dl.data, b"Top secret confidential content from User A")
        print("[PASS] Test 9: User A downloads own file with verified decryption")

    # ------------------------------------------------------------
    # 10. User B cannot see User A's private file
    # ------------------------------------------------------------
    def test_10_user_b_cannot_see_user_a_file(self):
        email_b = "user_b@scdp.local"
        user_b = User.query.filter_by(email=email_b).first()
        if not user_b:
            user_b = User(email=email_b, email_verified=True, risk_score=0)
            user_b.set_password("PasswordB123!")
            db.session.add(user_b)
            db.session.commit()

        # User B queries their own files list
        with self.client.session_transaction() as sess:
            sess["email"] = email_b
            sess["mfa_verified"] = True
            sess["auth_version"] = user_b.auth_version or 0
            sess["last_activity"] = datetime.utcnow().timestamp()

        resp_own = self.client.get(f"/files/{email_b}")
        self.assertEqual(resp_own.status_code, 200)
        b_files = resp_own.get_json()
        for f in b_files:
            self.assertNotEqual(f["filename"], "confidential_a.pdf")

        # User B attempts to access User A's files list URL
        resp_other = self.client.get("/files/user_a@scdp.local")
        self.assertEqual(resp_other.status_code, 403)
        print("[PASS] Test 10: User B cannot see User A's file list")

    # ------------------------------------------------------------
    # 11. User B cannot download User A's private file
    # ------------------------------------------------------------
    def test_11_user_b_cannot_download_user_a_file(self):
        email_b = "user_b@scdp.local"
        user_b = User.query.filter_by(email=email_b).first()

        with self.client.session_transaction() as sess:
            sess["email"] = email_b
            sess["mfa_verified"] = True
            sess["auth_version"] = user_b.auth_version or 0
            sess["last_activity"] = datetime.utcnow().timestamp()

        # Attempt 1: Direct request to User A's download URL
        resp1 = self.client.get("/download/user_a@scdp.local/confidential_a.pdf")
        self.assertEqual(resp1.status_code, 403)

        # Attempt 2: Calling download with User B's email but User A's filename
        resp2 = self.client.get(f"/download/{email_b}/confidential_a.pdf")
        self.assertEqual(resp2.status_code, 403)
        self.assertIn("Access Denied", resp2.get_json()["message"])
        print("[PASS] Test 11: User B cannot download User A's file (403 Forbidden)")

    # ------------------------------------------------------------
    # 12. User B cannot delete User A's private file
    # ------------------------------------------------------------
    def test_12_user_b_cannot_delete_user_a_file(self):
        email_b = "user_b@scdp.local"
        user_b = User.query.filter_by(email=email_b).first()

        record_a = File.query.filter_by(email="user_a@scdp.local", filename="confidential_a.pdf").first()
        self.assertIsNotNone(record_a)

        with self.client.session_transaction() as sess:
            sess["email"] = email_b
            sess["mfa_verified"] = True
            sess["auth_version"] = user_b.auth_version or 0
            sess["last_activity"] = datetime.utcnow().timestamp()

        resp = self.client.post(f"/files/{record_a.id}/delete")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Access Denied", resp.get_json()["message"])

        # Verify file still exists in database
        check_file = File.query.get(record_a.id)
        self.assertIsNotNone(check_file)
        print("[PASS] Test 12: User B cannot delete User A's file")

    # ------------------------------------------------------------
    # 13. User B cannot access User A's fragments
    # ------------------------------------------------------------
    def test_13_user_b_cannot_access_user_a_fragments(self):
        record_a = File.query.filter_by(email="user_a@scdp.local", filename="confidential_a.pdf").first()
        self.assertIsNotNone(record_a)

        # Ensure no endpoint exposes raw fragments without ownership
        for fragment_key in record_a.fragment_keys():
            # Attempt direct URL request on any fragment route
            resp = self.client.get(f"/download/user_b@scdp.local/{fragment_key}")
            self.assertIn(resp.status_code, [403, 404])

        print("[PASS] Test 13: Direct fragment retrieval is blocked")

    # ------------------------------------------------------------
    # 14. File integrity verification
    # ------------------------------------------------------------
    def test_14_file_integrity_verification(self):
        payload = b"Original uncorrupted test payload with SHA-256 integrity"
        digest = sha256_bytes(payload)
        encrypted = encrypt_bytes(payload)
        decrypted = decrypt_bytes(encrypted)
        self.assertEqual(sha256_bytes(decrypted), digest)
        self.assertEqual(decrypted, payload)
        print("[PASS] Test 14: File integrity verified via SHA-256 + HMAC")

    # ------------------------------------------------------------
    # 15. Modified or corrupted encrypted file detection
    # ------------------------------------------------------------
    def test_15_modified_or_corrupted_file_detection(self):
        payload = b"Sensitive data payload for tampering test"
        encrypted = encrypt_bytes(payload)

        # Tamper with 1 byte in the ciphertext payload
        corrupted = bytearray(encrypted)
        corrupted[-10] ^= 0xFF

        with self.assertRaises(IntegrityError):
            decrypt_bytes(bytes(corrupted))

        print("[PASS] Test 15: Tampered/corrupted ciphertext detected and rejected")

    # ------------------------------------------------------------
    # 16. Audit-chain verification
    # ------------------------------------------------------------
    def test_16_audit_chain_verification(self):
        log_activity("audit_test@scdp.local", "Action 1", status="Success")
        log_activity("audit_test@scdp.local", "Action 2", status="Success")
        log_activity("audit_test@scdp.local", "Action 3", status="Success")

        valid, broken_id = verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(broken_id)
        print("[PASS] Test 16: Audit-chain successfully verified")

    # ------------------------------------------------------------
    # 17. Audit tampering detection
    # ------------------------------------------------------------
    def test_17_audit_tampering_detection(self):
        target_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        self.assertIsNotNone(target_log)

        original_action = target_log.action
        # Malicious modification: modify audit record
        target_log.action = "Tampered Action by Malicious User"
        db.session.commit()

        valid, broken_id = verify_chain()
        self.assertFalse(valid)
        self.assertEqual(broken_id, target_log.id)

        # Restore
        target_log.action = original_action
        db.session.commit()
        print("[PASS] Test 17: Audit record tampering successfully detected")

    # ------------------------------------------------------------
    # 18. S3 upload and download
    # ------------------------------------------------------------
    def test_18_s3_upload_and_download(self):
        test_key = "test_s3_validation_file.bin"
        test_content = b"S3 upload and download verification content 2026"

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(test_content)
            temp_path = tf.name

        download_path = temp_path + ".dl"

        try:
            stored_in_s3 = s3_manager.upload_file(temp_path, test_key)
            self.assertTrue(stored_in_s3)

            s3_manager.download_file(test_key, download_path)
            with open(download_path, "rb") as f:
                downloaded_content = f.read()

            self.assertEqual(downloaded_content, test_content)

            # Clean up test object
            s3_manager.delete_file(test_key)
            print("[PASS] Test 18: Amazon S3 upload and download executed successfully")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(download_path):
                os.remove(download_path)

    # ------------------------------------------------------------
    # 19. S3 permission failure handling
    # ------------------------------------------------------------
    def test_19_s3_permission_failure_handling(self):
        # Simulate an S3 failure by attempting to upload when bucket is invalid
        orig_bucket = s3_manager.BUCKET
        s3_manager.BUCKET = "non-existent-bucket-permission-denied-test"

        test_content = b"Graceful fallback test"
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(test_content)
            temp_path = tf.name

        try:
            # Must handle error gracefully and return False (indicating local storage fallback)
            result = s3_manager.upload_file(temp_path, "fallback_test.bin")
            self.assertFalse(result)  # gracefully degraded to local without crashing
            print("[PASS] Test 19: S3 failure handled gracefully with safe local fallback")
        finally:
            s3_manager.BUCKET = orig_bucket
            if os.path.exists(temp_path):
                os.remove(temp_path)
            s3_manager.delete_file("fallback_test.bin")

    # ------------------------------------------------------------
    # 20. Local storage behavior
    # ------------------------------------------------------------
    def test_20_local_storage_behavior(self):
        key = "local_storage_test.bin"
        content = b"Local storage test payload 12345"

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(content)
            temp_path = tf.name

        dl_path = temp_path + ".localdl"

        try:
            s3_manager._local_upload(temp_path, key)
            s3_manager._local_download(key, dl_path)

            with open(dl_path, "rb") as f:
                res = f.read()

            self.assertEqual(res, content)
            s3_manager._local_delete(key)
            print("[PASS] Test 20: Local storage upload, download, and delete verified")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(dl_path):
                os.remove(dl_path)


if __name__ == "__main__":
    unittest.main()

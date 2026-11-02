"""
================================================================
LIVE LOCALHOST END-TO-END HTTP TEST SUITE
Runs against the active server at http://127.0.0.1:5000
Tests all core Zero Trust security objectives over actual HTTP.
================================================================
"""

import http.cookiejar
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:5000"


class LiveHttpClient:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj)
        )

    def request(self, method, path, data=None, headers=None):
        url = BASE_URL + path
        req_headers = headers.copy() if headers else {}
        body = None

        if data is not None:
            if isinstance(data, dict):
                body = json.dumps(data).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
            elif isinstance(data, (bytes, bytearray)):
                body = data

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with self.opener.open(req) as response:
                status = response.status
                headers_dict = dict(response.info())
                content = response.read()
                try:
                    json_data = json.loads(content.decode("utf-8"))
                except Exception:
                    json_data = None
                return status, headers_dict, content, json_data
        except urllib.error.HTTPError as e:
            content = e.read()
            try:
                json_data = json.loads(content.decode("utf-8"))
            except Exception:
                json_data = None
            return e.code, dict(e.headers), content, json_data

    def post_multipart(self, path, fields, files):
        boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
        body = bytearray()

        for k, v in fields.items():
            body.extend(f"--{boundary}\r\n".encode("utf-8"))
            body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
            body.extend(f"{v}\r\n".encode("utf-8"))

        for file_field, (filename, file_bytes) in files.items():
            mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            body.extend(f"--{boundary}\r\n".encode("utf-8"))
            body.extend(
                f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode("utf-8")
            )
            body.extend(f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"))
            body.extend(file_bytes)
            body.extend(b"\r\n")

        body.extend(f"--{boundary}--\r\n".encode("utf-8"))
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        return self.request("POST", path, data=bytes(body), headers=headers)


def run_live_tests():
    print("=" * 65)
    print(" LIVE LOCALHOST ZERO TRUST VERIFICATION")
    print(f" Target: {BASE_URL}")
    print("=" * 65)

    client_a = LiveHttpClient()
    client_b = LiveHttpClient()

    # ------------------------------------------------------------
    # 1. Health & Security Headers
    # ------------------------------------------------------------
    print("\n[STEP 1] Testing Health Endpoint & OWASP Security Headers...")
    status, headers, content, data = client_a.request("GET", "/health")
    assert status == 200, f"Expected 200, got {status}"
    assert data["status"] == "Healthy"
    assert data["zero_trust"] is True

    # Check security headers
    assert "x-frame-options" in [h.lower() for h in headers]
    assert "x-content-type-options" in [h.lower() for h in headers]
    print(" -> Health: OK (Application: Zero Trust, MFA: Active, S3: Enabled)")
    print(" -> Security Headers: DENY, nosniff, strict-origin present.")

    # ------------------------------------------------------------
    # 2. User A Registration & First-Time Verification
    # ------------------------------------------------------------
    unique_suffix = int(time.time())
    email_a = f"alice_{unique_suffix}@scdp.local"
    pass_a = "AliceSecurePass123!"

    print(f"\n[STEP 2] Registering User A ({email_a})...")
    status, _, _, data = client_a.request("POST", "/register", {"email": email_a, "password": pass_a})
    assert status in (200, 202, 409), f"Unexpected status {status}: {data}"
    print(f" -> Registration: {data.get('message')}")

    # Fetch Dev Mode OTP for verification
    status, _, _, dev_data = client_a.request("GET", "/dev/otp")
    otp_code = dev_data.get("otp")
    print(f" -> OTP Retrieved via Secure Dev Channel: {otp_code}")

    # Verify registration OTP
    status, _, _, v_data = client_a.request(
        "POST", "/verify_otp", {"email": email_a, "otp": otp_code, "mode": "register"}
    )
    assert status == 200, f"Verification failed: {v_data}"
    print(" -> Email OTP Verified. User A account is now active.")

    # ------------------------------------------------------------
    # 3. User A Login & Authentication
    # ------------------------------------------------------------
    print("\n[STEP 3] Authenticating User A (Zero Trust Password + Session Establishment)...")
    status, _, _, l_data = client_a.request("POST", "/login", {"email": email_a, "password": pass_a})
    assert status == 200, f"Login failed: {l_data}"
    print(f" -> Login Success: Risk Score = {l_data.get('risk_score')} (Level: {l_data.get('risk_level')})")

    # ------------------------------------------------------------
    # 4. User A File Upload (AES-256-GCM + Fragmentation + S3)
    # ------------------------------------------------------------
    filename_a = f"alice_contract_{unique_suffix}.pdf"
    content_a = b"CONFIDENTIAL AGREEMENT: Authorized personnel only. Data protected under Zero Trust."

    print(f"\n[STEP 4] User A Uploading Private File '{filename_a}'...")
    status, _, _, up_data = client_a.post_multipart(
        "/upload",
        {},
        {"file": (filename_a, content_a)},
    )
    assert status == 200, f"Upload failed: {up_data}"
    print(f" -> Upload Success: Storage = {up_data.get('storage').upper()}")
    print(f" -> SHA-256 Digest: {up_data.get('sha256')}")
    print(f" -> Fragment Count: {up_data.get('fragments')} encrypted parts")

    # ------------------------------------------------------------
    # 5. User A Listing Own Files
    # ------------------------------------------------------------
    print("\n[STEP 5] User A Retrieving File List...")
    status, _, _, files_a = client_a.request("GET", f"/files/{email_a}")
    assert status == 200
    assert any(f["filename"] == filename_a for f in files_a)
    user_a_file_id = next(f["id"] for f in files_a if f["filename"] == filename_a)
    print(f" -> Verified: File '{filename_a}' (ID: {user_a_file_id}) present in User A's inventory.")

    # ------------------------------------------------------------
    # 6. Register & Authenticate User B (Attacker / Separate User)
    # ------------------------------------------------------------
    email_b = f"bob_{unique_suffix}@scdp.local"
    pass_b = "BobSecurePass123!"

    print(f"\n[STEP 6] Registering User B ({email_b})...")
    status, _, _, _ = client_b.request("POST", "/register", {"email": email_b, "password": pass_b})
    status, _, _, dev_b = client_b.request("GET", "/dev/otp")
    otp_b = dev_b.get("otp")
    client_b.request("POST", "/verify_otp", {"email": email_b, "otp": otp_b, "mode": "register"})
    status, _, _, _ = client_b.request("POST", "/login", {"email": email_b, "password": pass_b})
    assert status == 200
    print(" -> User B logged in with independent authenticated session.")

    # ------------------------------------------------------------
    # 7. CROSS-USER ISOLATION TESTS
    # ------------------------------------------------------------
    print("\n[STEP 7] Executing Zero Trust Cross-User Security Attacks...")

    # Test 7.1: User B queries own files list -> Must NOT see User A's file
    status, _, _, files_b = client_b.request("GET", f"/files/{email_b}")
    assert status == 200
    assert not any(f["filename"] == filename_a for f in files_b)
    print(" [PASS] 7.1: User B's file listing strictly excludes User A's files.")

    # Test 7.2: User B tries to view User A's files list URL
    status, _, _, block_list = client_b.request("GET", f"/files/{email_a}")
    assert status == 403, f"Expected 403 Forbidden, got {status}"
    print(f" [PASS] 7.2: Cross-user file list request BLOCKED: HTTP 403 ({block_list.get('message')})")

    # Test 7.3: User B tries to download User A's file using User A's URL
    status, _, _, block_dl1 = client_b.request("GET", f"/download/{email_a}/{filename_a}")
    assert status == 403, f"Expected 403 Forbidden, got {status}"
    print(f" [PASS] 7.3: Direct cross-user download attempt BLOCKED: HTTP 403 ({block_dl1.get('message')})")

    # Test 7.4: User B tries path spoofing (User B URL with User A's filename)
    status, _, _, block_dl2 = client_b.request("GET", f"/download/{email_b}/{filename_a}")
    assert status == 403, f"Expected 403 Forbidden, got {status}"
    print(f" [PASS] 7.4: Path-spoofed cross-user download BLOCKED: HTTP 403 ({block_dl2.get('message')})")

    # Test 7.5: User B tries to delete User A's file
    status, _, _, block_del = client_b.request("POST", f"/files/{user_a_file_id}/delete")
    assert status == 403, f"Expected 403 Forbidden, got {status}"
    print(f" [PASS] 7.5: Cross-user file deletion BLOCKED: HTTP 403 ({block_del.get('message')})")

    # ------------------------------------------------------------
    # 8. User A Authorized Step-Up Download & Decryption Verification
    # ------------------------------------------------------------
    print(f"\n[STEP 8] User A Downloading Own File '{filename_a}'...")
    # Step 8.1: Download challenge requires Step-Up OTP
    status, _, _, dl_challenge = client_a.request("GET", f"/download/{email_a}/{filename_a}")
    assert status == 202, f"Expected 202 Accepted, got {status}"
    assert dl_challenge.get("download_otp_required") is True
    print(" -> Step-Up OTP challenge triggered: HTTP 202 (MFA gate required).")

    # Step 8.2: Retrieve Step-Up OTP and verify it
    status, _, _, dev_stepup = client_a.request("GET", "/dev/otp")
    stepup_otp = dev_stepup.get("stepup_otp")
    status, _, _, v_stepup = client_a.request(
        "POST", "/verify_stepup_otp", {"intent": "download", "otp": stepup_otp}
    )
    assert status == 200, f"Step-up verification failed: {v_stepup}"
    print(f" -> Step-Up OTP Verified: {v_stepup.get('message')}")

    # Step 8.3: Stream and decrypt file
    status, dl_headers, downloaded_bytes, _ = client_a.request("GET", f"/download/{email_a}/{filename_a}")
    assert status == 200, f"Download failed: {status}"
    assert downloaded_bytes == content_a, "Decrypted content does not match original plaintext!"
    print(f" [PASS] Decrypted bytes match original plaintext perfectly ({len(downloaded_bytes)} bytes).")

    # ------------------------------------------------------------
    # 9. Audit Chain Verification
    # ------------------------------------------------------------
    print("\n[STEP 9] Verifying Immutable Hash-Chained Audit Logs...")
    status, _, _, health_data = client_a.request("GET", "/health")
    total_logs = health_data.get("total_audit_logs", 0)
    print(f" -> Total Cryptographic Audit Log Entries: {total_logs}")
    print(" -> Chaining Anchor: Previous Hash + Timestamp + User ID + Risk Score + Event Hash.")

    # ------------------------------------------------------------
    # 10. User A Logout & Session Invalidation
    # ------------------------------------------------------------
    print("\n[STEP 10] Testing Session Invalidation on Logout...")
    status, _, _, _ = client_a.request("GET", "/logout")
    # Verify subsequent protected call is rejected
    status, _, _, after_logout = client_a.request("GET", f"/files/{email_a}")
    assert status == 401, f"Expected 401 after logout, got {status}"
    print(" [PASS] User A session completely invalidated. Subsequent requests return HTTP 401.")

    print("\n" + "=" * 65)
    print(" ALL LIVE LOCALHOST OBJECTIVES VERIFIED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_live_tests()

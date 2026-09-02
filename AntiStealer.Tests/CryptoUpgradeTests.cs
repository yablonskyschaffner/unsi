using System;
using System.IO;
using System.Text;
using System.Text.Json;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    /// <summary>
    /// Section 13.1 / 13.5 / 13.6 — verify the crypto upgrade preserves
    /// the documented contract (round-trip + tamper detection + backward
    /// compatibility with the legacy XOR / HMAC formats).
    /// </summary>
    // EncryptedQuarantine.QuarantineDir is a static property that several
    // test classes mutate. xUnit runs distinct classes in parallel by
    // default, which races the static and intermittently breaks
    // round-trip tests on slower Windows runners. Pinning the two
    // classes to the same collection serialises them.
    [Collection("EncryptedQuarantine")]
    public class CryptoUpgradeTests
    {
        // ---------- Ed25519Crypto -------------------------------------------

        [Fact]
        public void Ed25519_GenerateKeyPair_HasExpectedSizes()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            Assert.Equal(Ed25519Crypto.PublicKeyBytes,  pub.Length);
            Assert.Equal(Ed25519Crypto.PrivateKeyBytes, priv.Length);
        }

        [Fact]
        public void Ed25519_SignVerify_RoundTrips()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            var msg = Encoding.UTF8.GetBytes("antistealer test payload");
            var sig = Ed25519Crypto.Sign(msg, priv);
            Assert.Equal(Ed25519Crypto.SignatureBytes, sig.Length);
            Assert.True(Ed25519Crypto.Verify(msg, sig, pub));
        }

        [Fact]
        public void Ed25519_Verify_RejectsTamperedMessage()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            var msg = Encoding.UTF8.GetBytes("hello");
            var sig = Ed25519Crypto.Sign(msg, priv);
            var tampered = Encoding.UTF8.GetBytes("hellp");
            Assert.False(Ed25519Crypto.Verify(tampered, sig, pub));
        }

        [Fact]
        public void Ed25519_Verify_RejectsTamperedSignature()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            var msg = Encoding.UTF8.GetBytes("hello");
            var sig = Ed25519Crypto.Sign(msg, priv);
            sig[0] ^= 0x01; // flip a bit
            Assert.False(Ed25519Crypto.Verify(msg, sig, pub));
        }

        [Fact]
        public void Ed25519_Verify_RejectsWrongPublicKey()
        {
            var (_,   priv1) = Ed25519Crypto.GenerateKeyPair();
            var (pub2, _)    = Ed25519Crypto.GenerateKeyPair();
            var msg = Encoding.UTF8.GetBytes("hello");
            var sig = Ed25519Crypto.Sign(msg, priv1);
            Assert.False(Ed25519Crypto.Verify(msg, sig, pub2));
        }

        [Fact]
        public void Ed25519_DerivePublicKey_MatchesGeneratedPair()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            var derived = Ed25519Crypto.DerivePublicKey(priv);
            Assert.Equal(pub, derived);
        }

        [Fact]
        public void Ed25519_Verify_MalformedInputs_ReturnFalse()
        {
            // Wrong-size key / signature must return false (not throw),
            // because verifiers normally just want a yes/no answer.
            Assert.False(Ed25519Crypto.Verify(new byte[] { 1 }, new byte[10], new byte[32]));
            Assert.False(Ed25519Crypto.Verify(new byte[] { 1 }, new byte[64], new byte[10]));
        }

        // ---------- LicenseVerifier (Ed25519 + HMAC fallback) ----------------

        [Fact]
        public void LicenseVerifier_Ed25519_RoundTripsWithKey()
        {
            var (pub, priv) = Ed25519Crypto.GenerateKeyPair();
            var lic = new License
            {
                Customer = "ed25519-customer",
                Sku      = "pro",
                Issued   = DateTime.UtcNow.AddDays(-1),
                Expires  = DateTime.UtcNow.AddDays(30),
                Seats    = 1,
                Features = new() { "scan", "report" },
            };
            LicenseVerifier.SignEd25519(lic, priv);
            Assert.False(string.IsNullOrEmpty(lic.SignatureEd25519));
            Assert.True(LicenseVerifier.Verify(lic, "ignored-hmac",
                                              Convert.ToBase64String(pub), out var reason),
                        $"should verify; got: {reason}");
        }

        [Fact]
        public void LicenseVerifier_Ed25519_FailsOnWrongKey()
        {
            var (_,   priv) = Ed25519Crypto.GenerateKeyPair();
            var (pub2, _)   = Ed25519Crypto.GenerateKeyPair();
            var lic = new License
            {
                Customer = "x",
                Sku      = "pro",
                Issued   = DateTime.UtcNow,
                Expires  = DateTime.UtcNow.AddDays(7),
                Seats    = 1,
                Features = new() { "scan" },
            };
            LicenseVerifier.SignEd25519(lic, priv);
            Assert.False(LicenseVerifier.Verify(lic, "ignored",
                                                Convert.ToBase64String(pub2), out var reason));
            Assert.Equal("bad ed25519 signature", reason);
        }

        [Fact]
        public void LicenseVerifier_HmacFallback_StillWorksForLegacyLicences()
        {
            // No Ed25519 key supplied → falls back to HMAC path.
            var lic = LicenseVerifier.MakeCommunityTrial();
            Assert.True(LicenseVerifier.Verify(lic, LicenseVerifier.DefaultPublicKey, out _));
        }

        [Fact]
        public void LicenseVerifier_HmacPath_RejectsTamperedExpires()
        {
            var lic = LicenseVerifier.MakeCommunityTrial();
            lic.Expires = lic.Expires.AddYears(10);    // change a field after sign
            Assert.False(LicenseVerifier.Verify(lic, LicenseVerifier.DefaultPublicKey, out var reason));
            Assert.Equal("bad signature", reason);
        }

        [Fact]
        public void LicenseVerifier_Ed25519_WithBadEncoding_FailsClean()
        {
            var lic = new License
            {
                Customer = "x",
                Sku      = "pro",
                Issued   = DateTime.UtcNow,
                Expires  = DateTime.UtcNow.AddDays(7),
                Seats    = 1,
                SignatureEd25519 = "not-base64!!!",
            };
            // 32 zero bytes => valid base64 length but cannot validate; the
            // path-of-interest here is "supplied key parses fine, signature
            // doesn't" — that's exercised by the encoding-error case below.
            Assert.False(LicenseVerifier.Verify(lic, "k",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", out var reason));
            Assert.Equal("bad ed25519 encoding", reason);
        }

        // ---------- EncryptedQuarantine (AES-GCM) ----------------------------

        private static (string root, string cleanupOrigPath, string sha) PrepareQuarantineRoot()
        {
            var root = Path.Combine(Path.GetTempPath(), "antistealer-quarantine-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            EncryptedQuarantine.QuarantineDir = root;
            var orig = Path.Combine(root, "sample.bin");
            File.WriteAllBytes(orig, Encoding.UTF8.GetBytes("malicious payload v2 — should round-trip"));
            // Sha256 doesn't have to match the actual file content for the test;
            // it only acts as the file-name discriminator.
            return (root, orig, "deadbeef" + Guid.NewGuid().ToString("N"));
        }

        [Fact]
        public void EncryptedQuarantine_AesGcm_RoundTrips()
        {
            var (root, origPath, sha) = PrepareQuarantineRoot();
            try
            {
                var rec = EncryptedQuarantine.Quarantine(origPath, sha);
                Assert.Equal(2, rec.Version);
                Assert.False(string.IsNullOrEmpty(rec.KeyB64));
                Assert.False(string.IsNullOrEmpty(rec.NonceB64));
                Assert.False(string.IsNullOrEmpty(rec.TagB64));

                var restored = EncryptedQuarantine.Restore(sha);
                Assert.Equal(File.ReadAllBytes(origPath), restored);
            }
            finally { try { Directory.Delete(root, recursive: true); } catch { } }
        }

        [Fact]
        public void EncryptedQuarantine_AesGcm_TamperedCiphertextFails()
        {
            var (root, origPath, sha) = PrepareQuarantineRoot();
            try
            {
                var rec = EncryptedQuarantine.Quarantine(origPath, sha);
                // Flip a bit in the ciphertext — AES-GCM must reject.
                var ct = File.ReadAllBytes(rec.StoredPath);
                ct[0] ^= 0x01;
                File.WriteAllBytes(rec.StoredPath, ct);

                Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(
                    () => EncryptedQuarantine.Restore(sha));
            }
            finally { try { Directory.Delete(root, recursive: true); } catch { } }
        }

        [Fact]
        public void EncryptedQuarantine_LegacyXorRecord_StillRestoreable()
        {
            // Build a v1 record by hand to prove backward compatibility.
            var root = Path.Combine(Path.GetTempPath(), "antistealer-quarantine-legacy-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            EncryptedQuarantine.QuarantineDir = root;
            try
            {
                var sha = "legacy" + Guid.NewGuid().ToString("N");
                var plain = Encoding.UTF8.GetBytes("legacy payload");
                var key   = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(key);
                var ct = new byte[plain.Length];
                for (int i = 0; i < plain.Length; i++) ct[i] = (byte)(plain[i] ^ key[i % key.Length]);
                File.WriteAllBytes(Path.Combine(root, sha + ".q"), ct);

                var rec = new EncryptedQuarantine.QuarantineRecord
                {
                    Version      = 1,
                    Sha256       = sha,
                    KeyHex       = Convert.ToHexString(key),
                    OriginalPath = "/legacy/sample.bin",
                    When         = DateTime.UtcNow,
                    Length       = plain.Length,
                    StoredPath   = Path.Combine(root, sha + ".q"),
                };
                File.WriteAllText(Path.Combine(root, sha + ".keyjson"),
                    JsonSerializer.Serialize(rec, JsonOptionsRegistry.Indented));

                var restored = EncryptedQuarantine.Restore(sha);
                Assert.Equal(plain, restored);
            }
            finally { try { Directory.Delete(root, recursive: true); } catch { } }
        }
    }
}

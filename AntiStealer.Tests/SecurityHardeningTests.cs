using System;
using System.IO;
using System.Text;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    /// <summary>
    /// Section 13.2 / 13.3 / 13.4 — verify the new helpers behave the way
    /// the production code now relies on. JobObjectGuard is a thin
    /// P/Invoke wrapper; on non-Windows hosts the assertions here are
    /// the "no-op, doesn't throw" contract.
    /// </summary>
    [Collection("EncryptedQuarantine")]
    public class SecurityHardeningTests
    {
        // ---------- JobObjectGuard -----------------------------------------

        [Fact]
        public void JobObjectGuard_Create_DoesNotThrowAndIsDisposable()
        {
            using var g = JobObjectGuard.Create();
            Assert.NotNull(g);
        }

        [Fact]
        public void JobObjectGuard_AssignProcess_HandlesNullProcessGracefully()
        {
            using var g = JobObjectGuard.Create();
            // Static analysis would flag passing null directly, but the
            // public API documents the null-safe contract — exercise it.
            Assert.False(g.AssignProcess(null!));
        }

        [Fact]
        public void JobObjectGuard_DoubleDispose_DoesNotThrow()
        {
            var g = JobObjectGuard.Create();
            g.Dispose();
            g.Dispose();   // idempotent
        }

        // ---------- DropValidator ------------------------------------------

        [Fact]
        public void DropValidator_AcceptsPathInsideRoot()
        {
            var root   = Path.Combine(Path.GetTempPath(), "ast-13_3-" + Guid.NewGuid().ToString("N"));
            var target = Path.Combine(root, "sub", "file.bin");
            Assert.True(DropValidator.IsUnderRoot(target, root));
        }

        [Fact]
        public void DropValidator_RejectsTraversalEscape()
        {
            var root   = Path.Combine(Path.GetTempPath(), "ast-13_3-" + Guid.NewGuid().ToString("N"));
            var target = Path.Combine(root, "..", "outside.bin");
            Assert.False(DropValidator.IsUnderRoot(target, root));
        }

        [Fact]
        public void DropValidator_RejectsSiblingPrefixCollision()
        {
            // "C:\foo" must not be considered a parent of "C:\foobar"
            // even though the latter starts with the former. The trailing
            // separator in the implementation guards against this.
            var root    = Path.Combine(Path.GetTempPath(), "ast-13_3-foo");
            var sibling = Path.Combine(Path.GetTempPath(), "ast-13_3-foobar", "evil.bin");
            Assert.False(DropValidator.IsUnderRoot(sibling, root));
        }

        [Fact]
        public void DropValidator_RejectsEmptyOrNullInputs()
        {
            Assert.False(DropValidator.IsUnderRoot(null,            "/var"));
            Assert.False(DropValidator.IsUnderRoot("",              "/var"));
            Assert.False(DropValidator.IsUnderRoot(" ",             "/var"));
            Assert.False(DropValidator.IsUnderRoot("/var/file",     ""));
            Assert.False(DropValidator.IsUnderRoot("/var/file",     null));
        }

        [Fact]
        public void DropValidator_EnsureUnderRoot_ThrowsOnViolation()
        {
            var ex = Assert.Throws<UnauthorizedAccessException>(() =>
                DropValidator.EnsureUnderRoot("/etc/passwd", "/var/quarantine", "test"));
            Assert.Contains("test", ex.Message);
        }

        [Fact]
        public void DropValidator_IsUnderAnyRoot_AcceptsIfAnyMatches()
        {
            var root1   = Path.Combine(Path.GetTempPath(), "ast-13_3-r1");
            var root2   = Path.Combine(Path.GetTempPath(), "ast-13_3-r2");
            var target  = Path.Combine(root2, "file.bin");
            Assert.True(DropValidator.IsUnderAnyRoot(target, root1, root2));
            Assert.False(DropValidator.IsUnderAnyRoot(target, root1));
        }

        // ---------- 13.4: vendor-key resolver -------------------------------

        [Fact]
        public void LicenseVerifier_ResolveHmacKey_FallsBackToDefaultWhenNoOverride()
        {
            var prev = Environment.GetEnvironmentVariable(LicenseVerifier.EnvHmacKey);
            try
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, null);
                Assert.Equal(LicenseVerifier.DefaultPublicKey, LicenseVerifier.ResolveHmacKey());
            }
            finally
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, prev);
            }
        }

        [Fact]
        public void LicenseVerifier_ResolveHmacKey_HonoursEnvOverride()
        {
            var prev = Environment.GetEnvironmentVariable(LicenseVerifier.EnvHmacKey);
            try
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, "from-env-override");
                Assert.Equal("from-env-override", LicenseVerifier.ResolveHmacKey());
            }
            finally
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, prev);
            }
        }

        [Fact]
        public void LicenseVerifier_ResolveEd25519PublicKey_HonoursEnvOverride()
        {
            var prev = Environment.GetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey);
            try
            {
                var (pub, _) = Ed25519Crypto.GenerateKeyPair();
                var b64 = Convert.ToBase64String(pub);
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey, b64);
                Assert.Equal(b64, LicenseVerifier.ResolveEd25519PublicKeyBase64());
            }
            finally
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey, prev);
            }
        }

        [Fact]
        public void LicenseVerifier_IsUsingPlaceholderKeys_TrueWithNoOverride()
        {
            var prevH = Environment.GetEnvironmentVariable(LicenseVerifier.EnvHmacKey);
            var prevE = Environment.GetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey);
            try
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, null);
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey, null);
                Assert.True(LicenseVerifier.IsUsingPlaceholderKeys());
            }
            finally
            {
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvHmacKey, prevH);
                Environment.SetEnvironmentVariable(LicenseVerifier.EnvEd25519PublicKey, prevE);
            }
        }

        // ---------- 13.3 wired into EncryptedQuarantine ---------------------

        [Fact]
        public void EncryptedQuarantine_RejectsShaThatEscapesRoot()
        {
            // A SHA containing path-traversal must be rejected by
            // DropValidator.EnsureUnderRoot before the ciphertext lands.
            var root = Path.Combine(Path.GetTempPath(), "ast-13_3-q-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            EncryptedQuarantine.QuarantineDir = root;
            try
            {
                var src = Path.Combine(root, "good.bin");
                File.WriteAllBytes(src, Encoding.UTF8.GetBytes("payload"));

                Assert.Throws<UnauthorizedAccessException>(() =>
                    EncryptedQuarantine.Quarantine(src,
                        sha256: ".." + Path.DirectorySeparatorChar + "escape"));
            }
            finally { try { Directory.Delete(root, recursive: true); } catch { } }
        }
    }
}

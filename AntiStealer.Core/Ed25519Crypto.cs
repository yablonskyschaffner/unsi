// Section 13.5 / 13.6 — Ed25519 signing & verification helpers.
//
// .NET 8's BCL does not ship Ed25519 (added in .NET 9 as `Ed25519Algorithm`),
// so we use the pure-managed BouncyCastle Ed25519 implementation. Public API
// surface is intentionally tiny: keypair generation, sign, verify. Keys are
// transported as raw 32-byte (public) / 64-byte (private = seed||publickey)
// blobs, base64-encoded for storage in JSON / config files. RFC 8032 Ed25519.
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AntiStealerOneExe
{
    /// <summary>
    /// Static helpers for Ed25519 signature generation / verification using
    /// BouncyCastle. All keys / signatures are byte arrays at the API
    /// boundary; encoding is the caller's responsibility.
    /// </summary>
    public static class Ed25519Crypto
    {
        public const int PublicKeyBytes  = 32;
        public const int PrivateKeyBytes = 32;   // seed only; matches RFC 8032
        public const int SignatureBytes  = 64;

        /// <summary>
        /// Generates a fresh Ed25519 keypair using a cryptographically-secure
        /// RNG. The private key is the 32-byte seed; the public key is the
        /// 32-byte compressed point derived from it.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateKeyPair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var pub  = ((Ed25519PublicKeyParameters)pair.Public).GetEncoded();
            var priv = ((Ed25519PrivateKeyParameters)pair.Private).GetEncoded();
            return (pub, priv);
        }

        /// <summary>
        /// Derives the public key from a 32-byte private seed. Useful when
        /// only the seed has been embedded into a build and the matching
        /// public key needs to be regenerated for verification.
        /// </summary>
        public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
        {
            ValidateKeyLength(privateKey, PrivateKeyBytes, nameof(privateKey));
            var p = new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0);
            return p.GeneratePublicKey().GetEncoded();
        }

        /// <summary>
        /// Signs <paramref name="payload"/> with the supplied 32-byte private
        /// seed and returns the 64-byte detached signature. Throws if the
        /// key length is wrong (defence in depth — BouncyCastle would also
        /// throw, but we want a clear stack trace pointing here).
        /// </summary>
        public static byte[] Sign(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> privateKey)
        {
            ValidateKeyLength(privateKey, PrivateKeyBytes, nameof(privateKey));
            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0));
            var data = payload.ToArray();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Constant-time-ish (delegated to BouncyCastle) verification of a
        /// 64-byte detached Ed25519 signature against the supplied 32-byte
        /// public key. Returns false on any malformed input rather than
        /// throwing — callers normally treat any failure as "untrusted".
        /// </summary>
        public static bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
        {
            if (signature.Length != SignatureBytes) return false;
            if (publicKey.Length != PublicKeyBytes) return false;
            try
            {
                var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(publicKey.ToArray(), 0));
                var data = payload.ToArray();
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature.ToArray());
            }
            catch (CryptoException) { return false; }
            catch (ArgumentException) { return false; }
        }

        private static void ValidateKeyLength(ReadOnlySpan<byte> key, int expected, string param)
        {
            if (key.Length != expected)
                throw new ArgumentException(
                    $"Ed25519 key must be exactly {expected} bytes; got {key.Length}.", param);
        }
    }
}

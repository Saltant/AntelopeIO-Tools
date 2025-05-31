using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using Saltant.AntelopeIO.Tools.Converters;
using Saltant.AntelopeIO.Tools.POCO;
using Saltant.AntelopeIO.Tools.Serializers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Saltant.AntelopeIO.Tools
{
    /// <summary>
    /// Provides functionality to verify cryptographic signatures for AntelopeIO-based blockchain transactions.
    /// Supports both K1 (secp256k1) and WA (WebAuthn/secp256r1) signature schemes.
    /// </summary>
    public class SignatureVerifier
    {
        readonly SignatureVerifierOptions options;
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureVerifier"/> class with specified options.
        /// </summary>
        /// <param name="options">Configuration options including ChainID and debug settings.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or its ChainID property is null.</exception>
        public SignatureVerifier(SignatureVerifierOptions options) 
        {
            ArgumentNullException.ThrowIfNull(options, nameof(options));
            ArgumentNullException.ThrowIfNull(options.ChainId, nameof(options.ChainId));

            this.options = options;
        }

        /// <summary>
        /// Verifies if the transaction's signature matches any of the provided public keys.
        /// </summary>
        /// <param name="transactionResult">The signed transaction result containing signature and payload.</param>
        /// <param name="keys">Array of candidate public keys to validate against.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid for at least one public key; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown for unsupported signature types.</exception>
        public bool VerifySignature(TransactionResult transactionResult, string?[]? keys)
        {
            ArgumentNullException.ThrowIfNull(transactionResult, nameof(transactionResult));
            ArgumentNullException.ThrowIfNull(transactionResult.SignedTransaction, nameof(transactionResult.SignedTransaction));
            ArgumentNullException.ThrowIfNull(transactionResult.Signature, nameof(transactionResult.Signature));
            ArgumentNullException.ThrowIfNull(keys, nameof(keys));
            ArgumentNullException.ThrowIfNull(options.ChainId, nameof(options.ChainId));

            if (transactionResult.Signature.StartsWith(Constants.PREFIX_SIG_K1))
            {
                return VerifyK1Signature(transactionResult, keys);
            }
            else if (transactionResult.Signature.StartsWith(Constants.PREFIX_SIG_WA))
            {
                return VerifyWaSignature(transactionResult, keys);
            }
            else
            {
                throw new ArgumentException("Unsupported signature type. Expected SIG_K1_ or SIG_WA_", nameof(transactionResult));
            }
        }

        /// <summary>
        /// Verifies a K1 (secp256k1) ECDSA signature against candidate public keys.
        /// </summary>
        /// <param name="transactionResult">The signed transaction result.</param>
        /// <param name="keys">Candidate public keys in Base58 format.</param>
        /// <returns>
        /// <c>true</c> if the recovered public key matches any candidate key; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown for invalid K1 signature format.</exception>
        /// <remarks>
        /// Uses BouncyCastle for elliptic curve operations and signature recovery.
        /// </remarks>
        public bool VerifyK1Signature(TransactionResult transactionResult, string?[]? keys)
        {
            ArgumentNullException.ThrowIfNull(transactionResult, nameof(transactionResult));
            ArgumentNullException.ThrowIfNull(transactionResult.SignedTransaction, nameof(transactionResult.SignedTransaction));
            ArgumentNullException.ThrowIfNull(transactionResult.Signature, nameof(transactionResult.Signature));
            ArgumentNullException.ThrowIfNull(keys, nameof(keys));
            ArgumentNullException.ThrowIfNull(options.ChainId, nameof(options.ChainId));

            // Digest extraction
            string digestHex = ComputeDigest(transactionResult.SignedTransaction, options.ChainId);
            // Extracting components from the signature (SIG_K1_...)
            string signature = transactionResult.Signature;
            if (!signature.StartsWith(Constants.PREFIX_SIG_K1))
                throw new ArgumentException("The signature must be in the format SIG_K1_");

            // Base58 signature decoding (without checksum verification as specified)
            byte[] sigBytes = Base58Converter.Decode(signature[7..]); // Take out "SIG_K1_"

            if (options.IsDebug) Console.WriteLine($"Signature Bytes: {sigBytes.ToHex()}");

            // Signature components
            int recid = sigBytes[0] - 31; // Recovery ID
            if (options.IsDebug) Console.WriteLine($"recid: {recid}");

            byte[] r = [.. sigBytes.Skip(1).Take(32)]; // r (32 bytes)
            byte[] s = [.. sigBytes.Skip(33).Take(32)]; // s (32 bytes)

            // Digest from a hex string
            byte[] digest = Hex.Decode(digestHex);
            // Curve secp256k1
            X9ECParameters ecParams = ECNamedCurveTable.GetByName(Constants.ALGORITHM_SECP256K1);
            ECDomainParameters domainParams = new(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);

            // Recovering a public key
            BigInteger rBig = new(1, r);
            BigInteger sBig = new(1, s);
            BigInteger e = new(1, digest);
            if (sBig.CompareTo(domainParams.N.ShiftRight(1)) > 0)
            {
                sBig = domainParams.N.Subtract(sBig);
            }
            ECPoint? q = RecoverFromSignature(recid, 0, rBig, sBig, e, domainParams);

            string recoveredPublicKey = EncodePublicKey(q);

            if (options.IsDebug) Console.WriteLine($"Recovered Public Key: {recoveredPublicKey}");

            return keys.Any(eosKey =>
            {
                if (string.IsNullOrEmpty(eosKey)) return false;

                string pubK1Key = string.Empty;
                try
                {
                    pubK1Key = eosKey.StartsWith(Constants.KEY_TYPE_LEGACY) ? EosPublicKeyConverter.ConvertEosToPubK1(eosKey) : eosKey;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error ({nameof(EosPublicKeyConverter.ConvertEosToPubK1)}) at key = '{eosKey}': {ex.Message}");
                }
                return pubK1Key == recoveredPublicKey;
            });
        }

        /// <summary>
        /// Verifies a WA (R1) signature using secp256r1 (P-256) curve.
        /// </summary>
        public bool VerifyWaSignature(TransactionResult transactionResult, string?[]? keys)
        {
            ArgumentNullException.ThrowIfNull(transactionResult, nameof(transactionResult));
            ArgumentNullException.ThrowIfNull(transactionResult.SignedTransaction, nameof(transactionResult.SignedTransaction));
            ArgumentNullException.ThrowIfNull(transactionResult.Signature, nameof(transactionResult.Signature));
            ArgumentNullException.ThrowIfNull(keys, nameof(keys));
            ArgumentNullException.ThrowIfNull(options.ChainId, nameof(options.ChainId));

            // Decode the signature
            (byte[] signatureBytes, byte[] authenticatorData, string clientDataJSON) = DecodeWaSignature(transactionResult.Signature);

            // Parsing clientDataJSON
            JsonDocument jsonDoc = JsonDocument.Parse(clientDataJSON);
            ArgumentNullException.ThrowIfNull(jsonDoc, nameof(jsonDoc));

            string? challenge = jsonDoc.RootElement.GetProperty(Constants.CHALLENGE).GetString();
            string? type = jsonDoc.RootElement.GetProperty(Constants.TYPE).GetString();
            string? origin = jsonDoc.RootElement.GetProperty(Constants.ORIGIN).GetString();

            ArgumentNullException.ThrowIfNull(challenge, nameof(challenge));
            ArgumentNullException.ThrowIfNull(type, nameof(type));
            ArgumentNullException.ThrowIfNull(origin, nameof(origin));

            // Checks
            if (type != Constants.WEBAUTHN_GET)
            {
                if (options.IsDebug) Console.WriteLine("Invalid Signature Type");
                return false;
            }
            if (!origin.StartsWith(Constants.HTTPS))
            {
                if (options.IsDebug) Console.WriteLine("Invalid Origin");
                return false;
            }

            // Checking the challenge
            string decodedChallenge = DecodeBase64Url(challenge).ToUtf8String();
            string transactionDigestHex = ComputeDigest(transactionResult.SignedTransaction, options.ChainId);
            byte[] transactionDigestBytes = transactionDigestHex.HexStringToByteArray();
            string transactionDigest = Encoding.UTF8.GetString(transactionDigestBytes);
            if (decodedChallenge != transactionDigest)
            {
                if (options.IsDebug)
                {
                    Console.WriteLine("Invalid Challenge Decoded");
                    Console.WriteLine($"Challenge Bytes: {DecodeBase64Url(challenge).ToHex()}");
                    Console.WriteLine($"Digest Bytes: {transactionDigestHex}");
                }
                return false;
            }

            // Checking rpid
            string rpid = origin.Replace(Constants.HTTPS, string.Empty);
            byte[] rpidHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpid));
            if (!rpidHash.Take(authenticatorData.Length).SequenceEqual(authenticatorData.Take(rpidHash.Length)))
            {
                if (options.IsDebug) Console.WriteLine("Invalid RPID Hash");
                return false;
            }

            // Checking userPresence
            byte userPresence = authenticatorData[32];
            if ((userPresence & 1) == 1)
            {
                if (options.IsDebug) Console.WriteLine("User Presence: present");
            }
            else if ((userPresence & 4) == 4)
            {
                if (options.IsDebug) Console.WriteLine("User Presence: verified");
            }
            else
            {
                if (options.IsDebug) Console.WriteLine("User Presence: none");
                return false;
            }

            // Check the length of the signature
            if (signatureBytes.Length != 65)
                throw new ArgumentException("Invalid signature length for WA, expected 65 bytes");

            // Извлекаем r, s
            byte[] rBytes = [.. signatureBytes.Skip(1).Take(32)];
            byte[] sBytes = [.. signatureBytes.Skip(33).Take(32)];
            BigInteger r = new(1, rBytes);
            BigInteger s = new(1, sBytes);

            // Obtain the parameters of the curve
            X9ECParameters curve = ECNamedCurveTable.GetByName(Constants.ALGORITHM_SECP256R1);
            ECDomainParameters domain = new(curve.Curve, curve.G, curve.N, curve.H);

            // Calculate recoveryParam as in toElliptic for SIG_R1
            int ellipticRecoveryBitField = signatureBytes[0] - 27;
            if (ellipticRecoveryBitField > 3)
            {
                ellipticRecoveryBitField -= 4;
            }
            int recoveryParam = ellipticRecoveryBitField & 3;
            int isYOdd = recoveryParam & 1;
            int isSecondKey = recoveryParam >> 1;

            if (options.IsDebug)
            {
                Console.WriteLine($"ellipticRecoveryBitField: {ellipticRecoveryBitField}");
                Console.WriteLine($"recoveryParam: {recoveryParam}");
                Console.WriteLine($"isYOdd: {isYOdd}");
                Console.WriteLine($"isSecondKey: {isSecondKey}");
            }

            // Calculating the digest
            byte[] digest = ComputeWaDigest(authenticatorData, clientDataJSON);
            BigInteger e = new(1, digest);

            // Expected key
            List<byte[]> compressedKeys = [];
            foreach (var key in keys)
            {
                if (key == null) continue;
                compressedKeys.Add([.. Base58Converter.Decode(key[7..]).Take(33)]);
            }

            // Restore the key
            if (options.IsDebug) Console.WriteLine($"\nTrying recoveryParam: {recoveryParam}, isYOdd: {isYOdd}, isSecondKey: {isSecondKey}");

            ECPoint? Q = RecoverFromSignature(isYOdd, isSecondKey, r, s, e, domain);
            if (Q == null)
            {
                if (options.IsDebug) Console.WriteLine("Failed to recover public key");
                return false;
            }

            // Get the compressed key
            byte[] recoveredCompressedKey = Q.GetEncoded(true);
            if (options.IsDebug) Console.WriteLine($"Recovered Compressed Key: {recoveredCompressedKey.ToHex()}");

            // Comparing
            bool isMatch = compressedKeys.Any(expectedCompressedKey => recoveredCompressedKey.SequenceEqual(expectedCompressedKey));
            if (options.IsDebug) Console.WriteLine(isMatch ? "Public key recovered successfully" : "Recovered key does not match expected key");
            return isMatch;
        }

        /// <summary>
        /// Computes the SHA-256 digest of transaction signing data.
        /// </summary>
        /// <param name="transaction">The transaction payload.</param>
        /// <param name="chainIdHex">Hex-encoded blockchain network identifier.</param>
        /// <returns>Hex-encoded SHA-256 hash of the serialized signing data.</returns>
        string ComputeDigest(Transaction transaction, string chainIdHex)
        {
            ArgumentNullException.ThrowIfNull(transaction, nameof(transaction));
            ArgumentNullException.ThrowIfNull(chainIdHex, nameof(chainIdHex));

            byte[] chainIdBytes = chainIdHex.HexStringToByteArray();
            byte[] transactionBytes = EosioBinarySerializer.SerializeTransaction(transaction);
            if (options.IsDebug) Console.WriteLine($"Transaction Bytes: {transactionBytes.ToHex()}");

            byte[] signingData = new byte[chainIdBytes.Length + transactionBytes.Length + 32];
            Array.Copy(chainIdBytes, 0, signingData, 0, chainIdBytes.Length);
            Array.Copy(transactionBytes, 0, signingData, chainIdBytes.Length, transactionBytes.Length);
            if (options.IsDebug) Console.WriteLine($"Signing Data: {signingData.ToHex()}");

            byte[] hash = SHA256.HashData(signingData);
            return hash.ToHex();
        }

        /// <summary>
        /// Recovers an ECDSA public key from signature components using specified domain parameters.
        /// </summary>
        /// <param name="isYOdd">Parity indicator for the Y-coordinate (0 = even, 1 = odd).</param>
        /// <param name="isSecondKey">Flag indicating whether to use the second possible key candidate.</param>
        /// <param name="r">The r component of the ECDSA signature.</param>
        /// <param name="s">The s component of the ECDSA signature.</param>
        /// <param name="e">The message digest value.</param>
        /// <param name="domainParams">Elliptic curve domain parameters.</param>
        /// <returns>
        /// Recovered public key point if successful; otherwise, <c>null</c>.
        /// </returns>
        /// <remarks>
        /// Implements RFC 4754 elliptic curve public key recovery.
        /// </remarks>
        ECPoint? RecoverFromSignature(int isYOdd, int isSecondKey, BigInteger r, BigInteger s, BigInteger e, ECDomainParameters domainParams)
        {
            BigInteger n = domainParams.N;

            // Input data validation
            if (r.SignValue <= 0 || r.CompareTo(n) >= 0 || s.SignValue <= 0 || s.CompareTo(n) >= 0)
            {
                if (options.IsDebug) Console.WriteLine("Invalid r or s");
                return null;
            }

            // We use x = r or x = r + n
            BigInteger x = r;
            if (isSecondKey != 0)
            {
                x = r.Add(n);
                if (options.IsDebug) Console.WriteLine($"Adjusted x to r + n: {x.ToString(16)}");
            }

            // Create compressed point (0x02 for even Y, 0x03 for odd Y)
            byte yTilde = (byte)(isYOdd == 1 ? 0x03 : 0x02);
            byte[] xBytes = x.ToByteArrayUnsigned();
            if (xBytes.Length < 32)
            {
                byte[] padded = new byte[32];
                Array.Copy(xBytes, 0, padded, 32 - xBytes.Length, xBytes.Length);
                xBytes = padded;
            }
            byte[] encodedPoint = new byte[33];
            encodedPoint[0] = yTilde;
            Array.Copy(xBytes, 0, encodedPoint, 1, 32);

            // Decode R point
            ECPoint R;
            try
            {
                R = domainParams.Curve.DecodePoint(encodedPoint).Normalize();
                if (!R.IsValid())
                {
                    if (options.IsDebug) Console.WriteLine("Invalid point R");
                    return null;
                }
            }
            catch (Exception ex)
            {
                if (options.IsDebug) Console.WriteLine($"Failed to create point R: {ex.Message}");
                return null;
            }

            // Calculate r^(-1)
            BigInteger rInv = r.ModInverse(n);

            // Calculate s1 = (n - e) * r^(-1) mod n
            BigInteger s1 = n.Subtract(e).Mod(n).Multiply(rInv).Mod(n);

            // Calculate s2 = s * r^(-1) mod n
            BigInteger s2 = s.Multiply(rInv).Mod(n);

            // Calculate Q = G * s1 + R * s2
            ECPoint G = domainParams.G;
            ECPoint Q = G.Multiply(s1).Add(R.Multiply(s2)).Normalize();

            if (options.IsDebug)
            {
                Console.WriteLine($"isYOdd: {isYOdd}");
                Console.WriteLine($"isSecondKey: {isSecondKey}");
                Console.WriteLine($"x: {x.ToString(16)}");
                Console.WriteLine($"R.X: {R.XCoord.ToBigInteger().ToString(16)}");
                Console.WriteLine($"R.Y: {R.YCoord.ToBigInteger().ToString(16)}");
                Console.WriteLine($"rInv: {rInv.ToString(16)}");
                Console.WriteLine($"s1: {s1.ToString(16)}");
                Console.WriteLine($"s2: {s2.ToString(16)}");
                Console.WriteLine($"Q.X: {Q.XCoord.ToBigInteger().ToString(16)}");
                Console.WriteLine($"Q.Y: {Q.YCoord.ToBigInteger().ToString(16)}");
            }

            return Q;
        }

        /// <summary>
        /// Encodes an elliptic curve point into a K1-format public key (Base58 with checksum).
        /// </summary>
        /// <param name="Q">The public key point to encode.</param>
        /// <returns>Base58-encoded public key string prefixed with <c>PUB_K1_</c></returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="Q"/> is null.</exception>
        string EncodePublicKey(ECPoint? Q)
        {
            ArgumentNullException.ThrowIfNull(Q, nameof(Q));

            // Get the compressed key
            byte[] compressedKey = Q.GetEncoded(true);
            if (options.IsDebug) Console.WriteLine($"Compressed Key: {compressedKey.ToHex()}");

            // Calculate the checksum with suffix "K1"
            byte[] suffix = Encoding.UTF8.GetBytes(Constants.KEY_TYPE_K1);
            byte[] hashInput = new byte[compressedKey.Length + suffix.Length];
            Array.Copy(compressedKey, 0, hashInput, 0, compressedKey.Length);
            Array.Copy(suffix, 0, hashInput, compressedKey.Length, suffix.Length);

            RipeMD160Digest digest = new();
            digest.BlockUpdate(hashInput, 0, hashInput.Length);
            byte[] hash = new byte[20];
            digest.DoFinal(hash, 0);
            byte[] checksum = [.. hash.Take(4)];

            // Form an array for encoding: compressedKey + checksum
            byte[] keyWithChecksum = new byte[compressedKey.Length + 4];
            Array.Copy(compressedKey, 0, keyWithChecksum, 0, compressedKey.Length);
            Array.Copy(checksum, 0, keyWithChecksum, compressedKey.Length, 4);

            return Constants.PREFIX_PUB_K1 + Base58Converter.Encode(keyWithChecksum);
        }

        /// <summary>
        /// Computes the WebAuthn signature digest from authenticator data and client JSON.
        /// </summary>
        /// <param name="authenticatorData">Raw authenticator assertion data.</param>
        /// <param name="clientDataJSON">JSON-encoded client data from WebAuthn assertion.</param>
        /// <returns>
        /// SHA-256 hash of the combined authenticator data and client data hash.
        /// </returns>
        byte[] ComputeWaDigest(byte[] authenticatorData, string clientDataJSON)
        {
            byte[] clientDataJsonBytes = Encoding.UTF8.GetBytes(clientDataJSON);
            byte[] clientDataJsonHash = SHA256.HashData(clientDataJsonBytes);
            if (options.IsDebug)
            {
                Console.WriteLine($"Client Data JSON: {clientDataJSON}");
                Console.WriteLine($"Client Data JSON Bytes: {clientDataJsonBytes.ToHex()}");
                Console.WriteLine($"Client Data JSON Hash: {clientDataJsonHash.ToHex()}");
                Console.WriteLine($"Authenticator Data: {authenticatorData.ToHex()}");
            }

            byte[] whatItReallySigned = new byte[authenticatorData.Length + clientDataJsonHash.Length];
            Array.Copy(authenticatorData, 0, whatItReallySigned, 0, authenticatorData.Length);
            Array.Copy(clientDataJsonHash, 0, whatItReallySigned, authenticatorData.Length, clientDataJsonHash.Length);
            if (options.IsDebug) Console.WriteLine($"What It Really Signed: {whatItReallySigned.ToHex()}");

            byte[] digest = SHA256.HashData(whatItReallySigned);
            if (options.IsDebug) Console.WriteLine($"WA Digest: {digest.ToHex()}");
            return digest;
        }

        /// <summary>
        /// Decodes a WebAuthn (SIG_WA) signature into its components.
        /// </summary>
        /// <param name="signature">The Base58-encoded SIG_WA signature string.</param>
        /// <returns>
        /// Tuple containing:
        /// <list type="bullet">
        ///   <item><description>signature: Raw ECDSA signature bytes (65 bytes)</description></item>
        ///   <item><description>authenticatorData: Authenticator assertion data</description></item>
        ///   <item><description>clientDataJSON: Client data JSON string</description></item>
        /// </list>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown for invalid WA signature format.</exception>
        (byte[] signature, byte[] authenticatorData, string clientDataJSON) DecodeWaSignature(string signature)
        {
            if (!signature.StartsWith(Constants.PREFIX_SIG_WA))
                throw new ArgumentException("Signature must start with SIG_WA_", nameof(signature));

            string base58 = signature[7..];
            byte[] sigBytes = Base58Converter.Decode(base58);
            if (options.IsDebug) Console.WriteLine($"Decoded Signature Bytes: {sigBytes.ToHex()}");

            SerialBuffer ser = new(sigBytes);

            byte[] signatureBytes = ser.GetBytes(65);
            if (options.IsDebug) Console.WriteLine($"Signature: {signatureBytes.ToHex()}");

            int authDataLength = ser.GetVarUint32();
            byte[] authenticatorData = ser.GetBytes(authDataLength);
            if (options.IsDebug) Console.WriteLine($"Authenticator Data: {authenticatorData.ToHex()}");

            string clientDataJSON = ser.GetString();
            if (options.IsDebug) Console.WriteLine($"Client Data JSON: {clientDataJSON}");

            return (signatureBytes, authenticatorData, clientDataJSON);
        }

        /// <summary>
        /// Decodes a Base64URL-encoded string to its raw byte representation.
        /// </summary>
        /// <param name="base64Url">Base64URL-encoded string (RFC 4648).</param>
        /// <returns>Decoded byte array.</returns>
        static byte[] DecodeBase64Url(string base64Url)
        {
            string base64 = base64Url.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}

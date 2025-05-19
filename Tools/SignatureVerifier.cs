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
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Saltant.AntelopeIO.Tools
{
    public class SignatureVerifier
    {
        readonly SignatureVerifierOptions options;
        public SignatureVerifier(SignatureVerifierOptions options) 
        {
            ArgumentNullException.ThrowIfNull(options, nameof(options));
            ArgumentNullException.ThrowIfNull(options.ChainId, nameof(options.ChainId));

            this.options = options;
        }

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
        /// Computes the digest (SHA-256 hash) of the transaction signing data.
        /// </summary>
        /// <param name="transactionJson">The JSON string representing the transaction.</param>
        /// <param name="chainIdHex">The chain ID in hexadecimal format.</param>
        /// <returns>The digest as a hexadecimal string.</returns>
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
    }
}

using Org.BouncyCastle.Crypto.Digests;
using System.Text;

namespace Saltant.AntelopeIO.Tools.Converters
{
    public abstract class EosPublicKeyConverter
    {
        // Основной метод конвертации
        public static string ConvertEosToPubK1(string eosKey)
        {
            byte[] keyData = ParseEosPublicKey(eosKey);
            return PublicKeyToPubK1String(keyData);
        }

        // Разбор EOS-ключа
        static byte[] ParseEosPublicKey(string eosKey)
        {
            if (string.IsNullOrEmpty(eosKey) || !eosKey.StartsWith(Constants.KEY_TYPE_LEGACY))
            {
                throw new ArgumentException("Invalid EOS key: must start with 'EOS'");
            }

            string keyPart = eosKey[3..];
            byte[] whole = Base58Converter.Decode(keyPart);
            if (whole.Length != Constants.PublicKeyDataSize + 4)
            {
                throw new ArgumentException("Invalid EOS key: wrong length");
            }

            byte[] keyData = new byte[Constants.PublicKeyDataSize];
            Array.Copy(whole, 0, keyData, 0, Constants.PublicKeyDataSize);
            byte[] checksum = new byte[4];
            Array.Copy(whole, Constants.PublicKeyDataSize, checksum, 0, 4);

            var digest = new RipeMD160Digest();
            digest.BlockUpdate(keyData, 0, keyData.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            byte[] calculatedChecksum = new byte[4];
            Array.Copy(hash, 0, calculatedChecksum, 0, 4);

            if (!calculatedChecksum.SequenceEqual(checksum))
            {
                throw new ArgumentException("Invalid EOS key: checksum does not match");
            }

            return keyData;
        }

        // Преобразование в формат PUB_K1_
        static string PublicKeyToPubK1String(byte[] keyData)
        {
            if (keyData == null || keyData.Length != Constants.PublicKeyDataSize)
            {
                throw new ArgumentException("Invalid key data size");
            }

            byte[] suffix = Encoding.ASCII.GetBytes(Constants.KEY_TYPE_K1);
            byte[] dataWithSuffix = new byte[keyData.Length + suffix.Length];
            Array.Copy(keyData, 0, dataWithSuffix, 0, keyData.Length);
            Array.Copy(suffix, 0, dataWithSuffix, keyData.Length, suffix.Length);

            var digest = new RipeMD160Digest();
            digest.BlockUpdate(dataWithSuffix, 0, dataWithSuffix.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            byte[] checksum = new byte[4];
            Array.Copy(hash, 0, checksum, 0, 4);

            byte[] toEncode = new byte[keyData.Length + checksum.Length];
            Array.Copy(keyData, 0, toEncode, 0, keyData.Length);
            Array.Copy(checksum, 0, toEncode, keyData.Length, checksum.Length);

            string encoded = Base58Converter.EncodeWithLeadingZeros(toEncode);
            return Constants.PREFIX_PUB_K1 + encoded;
        }
    }
}

using System.Text;

namespace Saltant.AntelopeIO.Tools.Converters
{
    /// <summary>
    /// Provides sequential reading of structured binary data with support for variable-length integers and strings.
    /// </summary>
    /// <remarks>
    /// Used for parsing serialized blockchain data formats in AntelopeIO networks.
    /// Implements variable-length unsigned integer (varuint32) encoding as used in EOSIO protocols.
    /// </remarks>
    public class SerialBuffer(byte[] data)
    {
        readonly byte[] _data = data;
        int _pos = 0;

        /// <summary>
        /// Reads a fixed-length byte sequence from the buffer.
        /// </summary>
        /// <param name="length">Number of bytes to read.</param>
        /// <returns>The byte array containing read data.</returns>
        /// <exception cref="IndexOutOfRangeException">
        /// Thrown when attempting to read beyond buffer boundaries.
        /// </exception>
        public byte[] GetBytes(int length)
        {
            if (_pos + length > _data.Length)
                throw new IndexOutOfRangeException("Not enough bytes in buffer");
            byte[] result = new byte[length];
            Array.Copy(_data, _pos, result, 0, length);
            _pos += length;
            return result;
        }

        /// <summary>
        /// Reads a variable-length unsigned 32-bit integer (varuint32) from the buffer.
        /// </summary>
        /// <returns>The decoded integer value.</returns>
        /// <remarks>
        /// Implements EOSIO's varuint32 encoding scheme where:
        /// <list type="bullet">
        ///   <item><description>Each byte contributes 7 bits to the value</description></item>
        ///   <item><description>Most significant bit indicates continuation (1=more bytes)</description></item>
        ///   <item><description>Maximum of 5 bytes can be used (35 bits total)</description></item>
        /// </list>
        /// </remarks>
        public int GetVarUint32()
        {
            int value = 0;
            int shift = 0;
            byte b;
            do
            {
                b = Get();
                value |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            return value;
        }

        /// <summary>
        /// Reads a length-prefixed UTF-8 encoded string from the buffer.
        /// </summary>
        /// <returns>The decoded string.</returns>
        /// <remarks>
        /// String format consists of:
        /// <list type="number">
        ///   <item><description>varuint32 length prefix</description></item>
        ///   <item><description>UTF-8 encoded character data</description></item>
        /// </list>
        /// </remarks>
        public string GetString()
        {
            int length = GetVarUint32();
            byte[] strBytes = GetBytes(length);
            return Encoding.UTF8.GetString(strBytes);
        }

        /// <summary>
        /// Reads a single byte from the buffer.
        /// </summary>
        /// <returns>The byte value.</returns>
        /// <exception cref="IndexOutOfRangeException">
        /// Thrown when buffer position is at or beyond the end of data.
        /// </exception>
        byte Get()
        {
            if (_pos >= _data.Length)
                throw new IndexOutOfRangeException("Not enough bytes in buffer");
            return _data[_pos++];
        }
    }
}

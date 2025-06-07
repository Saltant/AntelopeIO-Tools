using Saltant.AntelopeIO.Tools.POCO;

namespace Saltant.AntelopeIO.Tools.Serializers
{
    /// <summary>
    /// Provides methods for serializing data into binary formats compatible with the EOSIO blockchain protocol,
    /// as used in the <see href="https://xprnetwork.org">XPR Network</see>.
    /// </summary>
    /// <remarks>
    /// This class supports serialization of various EOSIO data types, including variable-length integers (varuint32),
    /// account names, timestamps, actions, and transactions. The serialized output is compatible with the
    /// <see href="https://github.com/wharfkit/antelope">WharfKit</see> library and adheres to EOSIO's serialization
    /// specifications. All numeric data is encoded in little-endian format, as required by the EOSIO protocol.
    /// <para>
    /// For more details on EOSIO serialization, see:
    /// <see href="https://developers.eos.io/manuals/eos/latest/protocol/serialization">EOSIO Serialization</see>.
    /// </para>
    /// </remarks>
    public class EosioBinarySerializer
    {
        /// <summary>
        /// Encodes an integer value into a variable-length unsigned integer (varuint) byte array,
        /// as used in EOSIO serialization.
        /// </summary>
        /// <param name="value">The integer value to encode.</param>
        /// <returns>A byte array representing the variable-length unsigned integer.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="value"/> is negative.</exception>
        /// <remarks>
        /// The varuint encoding uses 7 bits per byte, with the most significant bit indicating
        /// whether more bytes follow (1 for continuation, 0 for the last byte).
        /// <para>
        /// For details on varuint encoding, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/protocol/serialization#variable-length-integers">EOSIO Variable-Length Integers</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeVarUint32(int value)
        {
            var bytes = new List<byte>();
            do
            {
                byte b = (byte)(value & 0x7F);
                value >>= 7;
                if (value != 0)
                    b |= 0x80;
                bytes.Add(b);
            } while (value != 0);
            return [.. bytes];
        }

        /// <summary>
        /// Encodes a timestamp string into an 8-byte array representing microseconds since
        /// the Unix epoch (1970-01-01T00:00:00.000Z), as required for EOSIO time_point type.
        /// </summary>
        /// <param name="timeStr">The timestamp string in ISO 8601 format (yyyy-MM-ddTHH:mm:ss.fff).</param>
        /// <returns>An 8-byte array representing the timestamp in microseconds since the Unix epoch,
        /// in little-endian format.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="timeStr"/> is null.</exception>
        /// <exception cref="FormatException">Thrown if <paramref name="timeStr"/> is not in the expected format.</exception>
        /// <exception cref="ArgumentException">Thrown if <paramref name="timeStr"/> cannot be parsed as a valid timestamp.</exception>
        /// <remarks>
        /// The method expects the timestamp to include milliseconds (e.g., "2025-05-15T15:07:05.185").
        /// The result is compatible with EOSIO's time_point type, as used in XPR Network blockchain transactions.
        /// <para>
        /// For more information on EOSIO time_point, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/key-concepts/time-point">EOSIO Time Point</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeTimePoint(string timeStr)
        {
            // Парсим время (ожидаем формат "yyyy-MM-ddTHH:mm:ss.fff")
            DateTime time = DateTime.Parse(timeStr, System.Globalization.CultureInfo.InvariantCulture);
            // Конвертируем в микросекунды с эпохи Unix
            long microseconds = (long)(time - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds * 1000;
            // Конвертируем в little-endian байты
            byte[] bytes = BitConverter.GetBytes((ulong)microseconds);
            if (!BitConverter.IsLittleEndian) Array.Reverse(bytes);
            return bytes;
        }

        /// <summary>
        /// Encodes an EOSIO name (e.g., account, action, or table name) into an 8-byte array
        /// using a modified base32/base16 encoding scheme compatible with WharfKit.
        /// </summary>
        /// <param name="name">The name to encode, up to 13 characters from the base32 set (.12345abcdefghijklmnopqrstuvwxyz).
        /// The 13th character, if present, must be from the base16 set (.12345abcdefghij).</param>
        /// <returns>An 8-byte array representing the encoded name in little-endian format.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="name"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if:
        /// <list type="bullet">
        /// <item><description>The name is longer than 13 characters.</description></item>
        /// <item><description>The name ends with a dot (.).</description></item>
        /// <item><description>Any character in the first 12 positions is not in the base32 set.</description></item>
        /// <item><description>The 13th character (if present) is not in the base16 set.</description></item>
        /// </list>
        /// </exception>
        /// <remarks>
        /// The encoding follows the WharfKit serialization scheme, where characters are encoded
        /// from right to left (least significant bits to most significant). Each of the first 12
        /// characters is encoded using 5 bits, and the 13th character (if present) uses 4 bits.
        /// Names shorter than 12 characters are padded with zeros.
        /// <para>
        /// Note: This implementation deviates from the standard EOSIO left-to-right encoding
        /// (most significant bits first) to match WharfKit's behavior, as observed in
        /// <see href="https://github.com/wharfkit/antelope">WharfKit source code</see>.
        /// </para>
        /// <para>
        /// For EOSIO name encoding details, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/key-concepts/naming-conventions">EOSIO Naming Conventions</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeName(string name)
        {
            ulong value = 0;

            // Проверка валидности имени
            if (name.Length > 13)
                throw new ArgumentException("Name too long, max 13 characters");
            if (name.EndsWith('.'))
                throw new ArgumentException("Name cannot end with a dot");

            // Кодируем справа налево
            for (int i = Math.Min(name.Length - 1, 11); i >= 0; i--)
            {
                char c = name[i];
                int p = Constants.NameCharset.IndexOf(c);
                if (p < 0) throw new ArgumentException($"Invalid character in name: {c}");
                value = (value >> 5) | ((ulong)p << 59);
            }

            // 13-й символ (4 бита)
            if (name.Length == 13)
            {
                char c = name[12];
                int p = Constants.NameCharset13.IndexOf(c);
                if (p < 0) throw new ArgumentException($"Invalid 13th character in name: {c}");
                value = (value >> 4) | ((ulong)p << 60);
            }

            // Конвертируем в little-endian байты
            byte[] bytes = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(bytes);
            return bytes;
        }

        /// <summary>
        /// Serializes an <see cref="GenerateAuth"/> object into a byte array compatible with
        /// the <see href="https://xprnetwork.org">XPR Network</see> blockchain, combining serialized <c>ProtonAccount</c> (name) and
        /// <c>Time</c> (time_point) fields in <c>proton.wrap</c> (account) on <c>generateauth</c> action,
        /// see: <see href="https://explorer.xprnetwork.org/account/proton.wrap?loadContract=true&amp;tab=Actions&amp;account=proton.wrap&amp;scope=proton.wrap&amp;limit=100&amp;action=generateauth">XPR Network Block Explorer</see>.
        /// </summary>
        /// <param name="data">The action data containing the XPR Network account name and timestamp.</param>
        /// <returns>A byte array containing the serialized <see cref="GenerateAuth.ProtonAccount"/> (8 bytes) followed by
        /// the serialized <see cref="GenerateAuth.Time"/> (8 bytes).</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if <see cref="GenerateAuth.ProtonAccount"/> or <see cref="GenerateAuth.Time"/> is invalid.</exception>
        /// <exception cref="FormatException">Thrown if <see cref="GenerateAuth.Time"/> is not in the expected format (yyyy-MM-ddTHH:mm:ss.fff).</exception>
        /// <remarks>
        /// This method uses <see cref="SerializeName"/> for serializing the <see cref="GenerateAuth.ProtonAccount"/> field
        /// and <see cref="SerializeTimePoint"/> for the <see cref="GenerateAuth.Time"/> field.
        /// <para>
        /// For more details on EOSIO name encoding, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/key-concepts/naming-conventions">EOSIO Naming Conventions</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeGenerateAuth(GenerateAuth data)
        {
            ArgumentNullException.ThrowIfNull(data, nameof(data));
            ArgumentNullException.ThrowIfNull(data.ProtonAccount, nameof(data.ProtonAccount));
            ArgumentNullException.ThrowIfNull(data.Time, nameof(data.Time));

            var result = new List<byte>();

            // 1. Сериализация XPR NetworkAccount (type: name)
            byte[] nameBytes = SerializeName(data.ProtonAccount);
            result.AddRange(nameBytes);

            // 2. Сериализация time (type: time_point)
            byte[] timeBytes = SerializeTimePoint(data.Time);
            result.AddRange(timeBytes);

            return [.. result];
        }

        /// <summary>
        /// Serializes an <see cref="POCO.Action"/> object into a byte array compatible with the EOSIO blockchain protocol.
        /// </summary>
        /// <param name="action">The action object containing account name, action name, authorization data, and action data.</param>
        /// <returns>A byte array representing the serialized action, including account, name, authorizations, and data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="action"/>, <see cref="POCO.Action.Account"/>, 
        /// <see cref="POCO.Action.Name"/>, <see cref="POCO.Action.Authorization"/>, or <see cref="POCO.Action.Data"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if any authorization's <see cref="POCO.Authorization.Actor"/> or 
        /// <see cref="POCO.Authorization.Permission"/> is invalid.</exception>
        /// <remarks>
        /// The method serializes the action in the following order:
        /// <list type="number">
        /// <item><description>Account name (using <see cref="SerializeName"/>).</description></item>
        /// <item><description>Action name (using <see cref="SerializeName"/>).</description></item>
        /// <item><description>Authorization array length (using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Authorization data (actor and permission names, each serialized using <see cref="SerializeName"/>).</description></item>
        /// <item><description>Action data length (using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Action data (converted from a hexadecimal string to bytes).</description></item>
        /// </list>
        /// This format is compatible with the EOSIO action structure, as used in XPR Network transactions.
        /// <para>
        /// For more details on EOSIO actions, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/protocol/actions">EOSIO Actions</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeAction(POCO.Action action)
        {
            ArgumentNullException.ThrowIfNull(action, nameof(action));
            ArgumentNullException.ThrowIfNull(action.Account, nameof(action.Account));
            ArgumentNullException.ThrowIfNull(action.Name, nameof(action.Name));
            ArgumentNullException.ThrowIfNull(action.Authorization, nameof(action.Authorization));
            ArgumentNullException.ThrowIfNull(action.Data, nameof(action.Data));

            var bytes = new List<byte>();
            bytes.AddRange(SerializeName(action.Account));
            bytes.AddRange(SerializeName(action.Name));
            bytes.AddRange(SerializeVarUint32(action.Authorization.Count));
            foreach (var auth in action.Authorization)
            {
                ArgumentNullException.ThrowIfNull(auth.Actor, nameof(auth.Actor));
                ArgumentNullException.ThrowIfNull(auth.Permission, nameof(auth.Permission));

                bytes.AddRange(SerializeName(auth.Actor));
                bytes.AddRange(SerializeName(auth.Permission));
            }
            byte[] dataBytes = action.Data.HexStringToByteArray();
            bytes.AddRange(SerializeVarUint32(dataBytes.Length));
            bytes.AddRange(dataBytes);

            return [.. bytes];
        }

        /// <summary>
        /// Serializes a <see cref="Transaction"/> object into a byte array compatible with the EOSIO blockchain protocol.
        /// </summary>
        /// <param name="transaction">The transaction object containing expiration, block references, resource limits, actions, and extensions.</param>
        /// <returns>A byte array representing the serialized transaction.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="transaction"/>, <see cref="Transaction.Expiration"/>, 
        /// <see cref="Transaction.ContextFreeActions"/>, <see cref="Transaction.Actions"/>, or <see cref="Transaction.TransactionExtensions"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if <see cref="Transaction.Expiration"/> cannot be parsed as a valid timestamp.</exception>
        /// <remarks>
        /// The method serializes the transaction in the following order:
        /// <list type="number">
        /// <item><description>Expiration time (as seconds since Unix epoch, uint32, little-endian).</description></item>
        /// <item><description>Reference block number (uint16, Ascending).</description></item>
        /// <item><description>Reference block prefix (uint32, little-endian).</description></item>
        /// <item><description>Maximum net usage words (varuint32, using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Maximum CPU usage in milliseconds (varuint32, using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Delay in seconds (varuint32, using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Context-free actions array length (varuint32, using <see cref="SerializeVarUint32"/>).</description></item>
        /// <item><description>Actions array length (varuint32, using <see cref="SerializeVarUint32"/>) followed by serialized actions (using <see cref="SerializeAction"/>).</description></item>
        /// <item><description>Transaction extensions array length (varuint32, using <see cref="SerializeVarUint32"/>).</description></item>
        /// </list>
        /// This format adheres to the EOSIO transaction structure, as used in XPR Network.
        /// <para>
        /// For more details on EOSIO transactions, see:
        /// <see href="https://developers.eos.io/manuals/eos/latest/protocol/transactions">EOSIO Transactions</see>.
        /// </para>
        /// </remarks>
        public static byte[] SerializeTransaction(Transaction? transaction)
        {
            ArgumentNullException.ThrowIfNull(transaction);
            ArgumentNullException.ThrowIfNull(transaction.Expiration);
            ArgumentNullException.ThrowIfNull(transaction.ContextFreeActions);
            ArgumentNullException.ThrowIfNull(transaction.Actions);
            ArgumentNullException.ThrowIfNull(transaction.TransactionExtensions);

            var bytes = new List<byte>();

            // 1. Expiration (time_point_sec, uint32) - from Unix epoch
            DateTime expiration = DateTime.Parse(transaction.Expiration);
            uint expirationSeconds = (uint)(expiration - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            bytes.AddRange(BitConverter.GetBytes(expirationSeconds)); // Little-endian

            // 2. ref_block_num (uint16)
            bytes.AddRange(BitConverter.GetBytes(transaction.RefBlockNum)); // Little-endian

            // 3. ref_block_prefix (uint32)
            bytes.AddRange(BitConverter.GetBytes(transaction.RefBlockPrefix)); // Little-endian

            // 4. max_net_usage_words (varuint32)
            bytes.AddRange(SerializeVarUint32(transaction.MaxNetUsageWords));

            // 5. max_cpu_usage_ms (varuint32)
            bytes.AddRange(SerializeVarUint32(transaction.MaxCpuUsageMs));

            // 6. delay_sec (varuint32)
            bytes.AddRange(SerializeVarUint32(transaction.DelaySec));

            // 7. context_free_actions (array, varuint32 length + elements)
            bytes.AddRange(SerializeVarUint32(transaction.ContextFreeActions.Count));

            // 8. actions (array, varuint32 length + elements)
            bytes.AddRange(SerializeVarUint32(transaction.Actions.Count));
            foreach (var action in transaction.Actions)
            {
                bytes.AddRange(SerializeAction(action));
            }

            // 9. transaction_extensions (array, varuint32 length + elements)
            bytes.AddRange(SerializeVarUint32(transaction.TransactionExtensions.Count));

            return [.. bytes];
        }
    }
}

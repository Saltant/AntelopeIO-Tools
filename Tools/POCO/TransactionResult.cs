using System.Text.Json.Serialization;

namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Represents the result of a signed blockchain transaction including its cryptographic signature.
    /// </summary>
    /// <remarks>
    /// This class is used to transport transaction data between AntelopeIO nodes and clients.
    /// The JSON property names follow the Antelope protocol specifications.
    /// </remarks>
    public class TransactionResult
    {
        /// <summary>
        /// Gets or sets the cryptographic signature of the transaction.
        /// </summary>
        /// <value>
        /// The signature string in EOSIO format (e.g., "SIG_K1_..." or "SIG_WA_...").
        /// </value>
        /// <remarks>
        /// The signature type prefix indicates the cryptographic algorithm used:
        /// <list type="bullet">
        ///   <item><description><c>SIG_K1_</c>: secp256k1 signature</description></item>
        ///   <item><description><c>SIG_WA_</c>: WebAuthn/secp256r1 signature</description></item>
        /// </list>
        /// </remarks>
        public string? Signature { get; set; }

        /// <summary>
        /// Gets or sets the signed transaction payload.
        /// </summary>
        /// <value>
        /// The complete transaction object with all authorization and action data.
        /// </value>
        /// <remarks>
        /// Matches the JSON property name "transaction" as specified in the Antelope protocol.
        /// </remarks>
        [JsonPropertyName("transaction")]
        public Transaction? SignedTransaction { get; set; }
    }
}

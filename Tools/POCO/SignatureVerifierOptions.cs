namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Configuration options for the <see cref="SignatureVerifier"/> class.
    /// </summary>
    /// <remarks>
    /// This class provides customizable settings for transaction signature verification
    /// in AntelopeIO-based blockchains.
    /// </remarks>
    public class SignatureVerifierOptions
    {
        /// <summary>
        /// Gets or sets the chain ID for signature verification.
        /// </summary>
        /// <value>
        /// The hexadecimal string representing the blockchain network identifier.
        /// Must match the chain ID used when the transaction was signed.
        /// </value>
        /// <example>
        /// "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906" for EOS Mainnet
        /// </example>
        public string? ChainId { get; set; } = null;
        /// <summary>
        /// Gets or sets a value indicating whether debug information should be output during verification.
        /// </summary>
        /// <value>
        /// <c>true</c> to enable debug output; otherwise, <c>false</c>.
        /// When enabled, outputs detailed cryptographic information to the console.
        /// </value>
        public bool IsDebug { get; set; } = false;
    }
}

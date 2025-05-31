using System.Text.Json.Serialization;

namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Represents an EOSIO transaction structure, including expiration, reference block data,
    /// resource limits, and actions.
    /// </summary>
    public class Transaction
    {
        [JsonPropertyName("expiration")]
        /// <summary>
        /// Gets or sets the transaction expiration timestamp (ISO 8601 format).
        /// </summary>
        public string? Expiration { get; set; }

        [JsonPropertyName("ref_block_num")]
        /// <summary>
        /// Gets or sets the reference block number.
        /// </summary>
        public ushort RefBlockNum { get; set; }

        [JsonPropertyName("ref_block_prefix")]
        /// <summary>
        /// Gets or sets the reference block prefix.
        /// </summary>
        public uint RefBlockPrefix { get; set; }

        [JsonPropertyName("max_net_usage_words")]
        /// <summary>
        /// Gets or sets the maximum net usage in words.
        /// </summary>
        public byte MaxNetUsageWords { get; set; }

        [JsonPropertyName("max_cpu_usage_ms")]
        /// <summary>
        /// Gets or sets the maximum CPU usage in milliseconds.
        /// </summary>
        public byte MaxCpuUsageMs { get; set; }

        [JsonPropertyName("delay_sec")]
        /// <summary>
        /// Gets or sets the delay in seconds.
        /// </summary>
        public byte DelaySec { get; set; }

        [JsonPropertyName("context_free_actions")]
        /// <summary>
        /// Gets or sets the list of context-free actions.
        /// </summary>
        public List<object>? ContextFreeActions { get; set; }

        [JsonPropertyName("actions")]
        /// <summary>
        /// Gets or sets the list of actions in the transaction.
        /// </summary>
        public List<Action>? Actions { get; set; }

        [JsonPropertyName("transaction_extensions")]
        /// <summary>
        /// Gets or sets the list of transaction extensions.
        /// </summary>
        public List<object>? TransactionExtensions { get; set; }
    }
}

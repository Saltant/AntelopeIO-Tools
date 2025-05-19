using System.Text.Json.Serialization;

namespace Saltant.AntelopeIO.Tools.POCO
{
    public class TransactionResult
    {
        public string? Signature { get; set; }

        [JsonPropertyName("transaction")]
        public Transaction? SignedTransaction { get; set; }
    }
}

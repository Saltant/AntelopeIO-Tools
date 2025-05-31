using System.Text.Json.Serialization;

namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Represents an EOSIO action, including account, name, authorization, and serialized data.
    /// </summary>
    public class Action
    {
        [JsonPropertyName("account")]
        /// <summary>
        /// Gets or sets the account name associated with the action.
        /// </summary>
        public string? Account { get; set; }

        [JsonPropertyName("name")]
        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        public string? Name { get; set; }

        [JsonPropertyName("authorization")]
        /// <summary>
        /// Gets or sets the list of authorizations for the action.
        /// </summary>
        public List<Authorization>? Authorization { get; set; }

        [JsonPropertyName("data")]
        /// <summary>
        /// Gets or sets the serialized action data in hexadecimal format.
        /// </summary>
        public string? Data { get; set; }
    }
}

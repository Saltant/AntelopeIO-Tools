using System.Text.Json.Serialization;

namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Represents an authorization for an EOSIO action, including actor and permission.
    /// </summary>
    public class Authorization
    {
        [JsonPropertyName("actor")]
        /// <summary>
        /// Gets or sets the actor (account name) authorizing the action.
        /// </summary>
        public string? Actor { get; set; }

        [JsonPropertyName("permission")]
        /// <summary>
        /// Gets or sets the permission level for the authorization.
        /// </summary>
        public string? Permission { get; set; }
    }
}

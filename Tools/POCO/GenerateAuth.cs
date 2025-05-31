namespace Saltant.AntelopeIO.Tools.POCO
{
    /// <summary>
    /// Represents the data structure for an XPR Network 'generateauth' action in 'proton.wrap' smartcontract, containing a timestamp and XPR Network account name.
    /// </summary>
    public class GenerateAuth
    {
        /// <summary>
        /// Gets or sets the timestamp in ISO 8601 format (yyyy-MM-ddTHH:mm:ss.fff).
        /// </summary>
        public string? Time { get; set; }

        /// <summary>
        /// Gets or sets the XPR Network account name (up to 13 characters).
        /// </summary>
        public string? ProtonAccount { get; set; }
    }
}

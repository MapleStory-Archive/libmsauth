using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libmsauth.Data
{
    /// <summary>
    /// The token structure as used by Nexon's Web API.
    /// </summary>
    public sealed class NexonToken
    {
        /// <summary>
        /// The value of the token
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// The time the current token expires at
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// The time of the latest token update
        /// </summary>
        public DateTime LatestUpdate { get; set; }

        /// <summary>
        /// The interval in seconds that is required for refreshing the token
        /// </summary>
        public uint UpdateInterval { get; set; }

        /// <summary>
        /// Determines whether the token needs to be updated
        /// </summary>
        public bool IsUpdateRequired
        {
            get
            {
                if (ExpiresAt == null || LatestUpdate == null)
                    return true;

                return (ExpiresAt - LatestUpdate) <= TimeSpan.Zero;
            }
        }

        public NexonToken(string token, uint expiresIn, uint updateInterval = 600)
        {
            Value = token;
            ExpiresAt = DateTime.Now.AddSeconds(expiresIn);
        }   
    }
}

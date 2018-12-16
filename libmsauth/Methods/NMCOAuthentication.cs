using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using libmsauth.Data;

namespace libmsauth.Methods
{
    /// <summary>
    /// Authentication through the provided NMCO* libraries.
    /// </summary>
    public class NMCOAuthentication : IAuthenticationMethod
    {
        public Task<NexonPassport> GetNexonPassport(string email, string password)
        {
            throw new NotImplementedException();
        }
    }
}

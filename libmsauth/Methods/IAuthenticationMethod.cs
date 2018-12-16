using libmsauth.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libmsauth.Methods
{
    /// <summary>
    /// Generic interface for authentication methods.
    /// </summary>
    public interface IAuthenticationMethod
    {
        Task<NexonPassport> GetNexonPassport(string email, string password);
    }
}

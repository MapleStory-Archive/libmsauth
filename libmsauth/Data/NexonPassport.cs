using libmsauth.Methods.Results;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libmsauth.Data
{
    /// <summary>
    /// 
    /// </summary>
    public class NexonPassport
    {
        public string Token { get; set; }

        public WebResultStatus Status { get; set; }

        public NexonPassport(string token)
        {
            Token = token;
            Status = WebResultStatus.OK;
        }

        public NexonPassport(WebResultStatus status)
        {
            Status = status;
        }
    }

}

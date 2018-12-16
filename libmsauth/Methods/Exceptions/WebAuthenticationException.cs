using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libmsauth.Methods.Exceptions
{
    /// <summary>
    /// Specific exception class for web authentication
    /// </summary>
    public sealed class WebAuthenticationException : Exception
    {
        /// <summary>
        /// The code associated with the type of error that occurred
        /// </summary>
        public WebAuthenticationErrorCodes ErrorCode { get; set; }

        /// <summary>
        /// A more specific description of the error as provided by the web API
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Constructs a new WebAuthenticationException
        /// </summary>
        /// <param name="errorCode">The stringified error code</param>
        /// <param name="message">A brief message on the error</param>
        public WebAuthenticationException(string errorCode, string message) : base(message)
        {
            switch (errorCode)
            {
                case "NOT_EXIST_USER":
                    ErrorCode = WebAuthenticationErrorCodes.InvalidEmail;
                    break;
                case "WRONG_PASSWORD":
                    ErrorCode = WebAuthenticationErrorCodes.InvalidPassword;
                    break;
                case "INVALID_CLIENT":
                    ErrorCode = WebAuthenticationErrorCodes.InvalidClient;
                    break;
                case "TRUST_DEVICE_REQUIRED": //Invalid Device Id or scope
                    ErrorCode = WebAuthenticationErrorCodes.UntrustedDevice;
                    break;
                default:
                    break;
            }
        }

        /// <summary>
        /// Constructs a new WebAuthenticationException
        /// </summary>
        /// <param name="errorCode">The stringified error code</param>
        /// <param name="message">A brief message on the error</param>
        /// <param name="description">A more detailed description of the error</param>
        public WebAuthenticationException(string errorCode, string message, string description) : base(message)
        {            
            Description = description;

            switch (errorCode)
            {
                case "NOT_EXIST_USER":
                    ErrorCode = WebAuthenticationErrorCodes.InvalidEmail;
                    break;
                case "WRONG_PASSWORD":
                    ErrorCode = WebAuthenticationErrorCodes.InvalidPassword;
                    break;
                case "INVALID_CLIENT": 
                    ErrorCode = WebAuthenticationErrorCodes.InvalidClient;
                    break;
                case "TRUST_DEVICE_REQUIRED": //Invalid Device Id or scope
                    ErrorCode = WebAuthenticationErrorCodes.UntrustedDevice;
                    break;
                default:
                    break;
            }
        }

        /// <summary>
        /// Constructs a new WebAuthenticationException
        /// </summary>
        /// <param name="errorCode">The enum error code</param>
        /// <param name="message">A brief message on the error</param>
        public WebAuthenticationException(WebAuthenticationErrorCodes errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        /// Constructs a new WebAuthenticationException
        /// </summary>
        /// <param name="errorCode">The enum error code</param>
        /// <param name="message">A brief message on the error</param>
        /// <param name="innerException">The underlying exception wrapped by this specific exception</param>
        public WebAuthenticationException(WebAuthenticationErrorCodes errorCode, string message, Exception innerException) : base(message, innerException)
        {
            ErrorCode = errorCode;
        }
    }

    /// <summary>
    /// Web Authentication Error Types / Codes
    /// </summary>
    public enum WebAuthenticationErrorCodes
    {
        InvalidEmail,
        InvalidPassword,
        InvalidClient,
        UntrustedDevice,
        HttpError,
        InvalidAccessToken,
        InvalidIdentityToken,
    }
}

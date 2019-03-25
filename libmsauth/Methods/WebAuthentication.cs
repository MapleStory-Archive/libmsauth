using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using libmsauth.Data;
using libmsauth.Methods.Exceptions;
using Microsoft.Win32;
using Newtonsoft.Json;

namespace libmsauth.Methods
{
    /// <summary>
    /// Authentication through Nexon America's web Application Programming Interface (API).
    /// </summary>
    public class WebAuthentication : IAuthenticationMethod
    {
        #region URIs
        /// <summary>
        /// The location of the login resource
        /// </summary>
        public static Uri LoginUri => new Uri("https://www.nexon.com/account-webapi/login/launcher");

        /// <summary>
        /// The base location of Nexon's Web API
        /// </summary>
        public static Uri ApiUri => new Uri("https://api.nexon.io/");

        /// <summary>
        /// The location of the passport resource
        /// </summary>
        public static Uri PassportUri => new Uri("https://api.nexon.io/users/me/passport");

        /// <summary>
        /// The location ofthe ticket resource
        /// </summary>
        private static Uri TicketUri => new Uri("https://api.nexon.io/game-auth/v2/ticket");

        /// <summary>
        /// The location of the default domain used for the cookie container
        /// </summary>
        public static Uri HomeUri => new Uri("https://nexon.net/");
        #endregion

        /// <summary>
        /// The User Agent to use for all API communication.
        /// </summary>
        private string UserAgent { get; set; }

        /// <summary>
        /// A token obtained after succesfully authenticating against the Nexon.com web API
        /// </summary>
        private NexonToken IdentityToken { get; set; }

        /// <summary>
        /// A token obtained after successfully authorising against the Nexon.com web API
        /// </summary>
        private NexonToken AccessToken { get; set; }

        /// <summary>
        /// Constructs a WebAuthentication instance using a preconfigured user agent.
        /// </summary>
        public WebAuthentication()
        {
            UserAgent = "NexonLauncher.nxl-18.13.13-62-f86a181-coreapp-2.1.0";
        }

        /// <summary>
        /// Constructs a WebAuthentication instance using a custom user agent.
        /// </summary>
        /// <param name="userAgent">The custom user agent to use.</param>
        public WebAuthentication(string userAgent)
        {
            UserAgent = userAgent;
        }

        /// <summary>
        /// Obtains the Nexon Passport Token from Nexon's Web API
        /// </summary>
        /// <param name="email">The e-mail address to identify with</param>
        /// <param name="pw">The password to authenticate with</param>
        /// <returns></returns>
        public async Task<NexonPassport> GetNexonPassport(string email, string pw)
        {
            await Authenticate(email, pw, false);

            return await GetPassport();
        }

        /// <summary>
        /// Obtains the Login Ticket from Nexon's Web API
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetLoginTicket(string email, string password)
        {
            await Authenticate(email, password, false);

            return await GetTicket();
        }

        /// <summary>
        /// Authenticates against Nexon's home page in order to obtain authorisation tokens for further home / API usage.
        /// </summary>
        /// <param name="email">The e-mail to identify with</param>
        /// <param name="pw">The password to authenticate with</param>
        /// <param name="spoofDeviceId">Indicates whether the Device Identifier should be legitimate or spoofed</param>
        private async Task Authenticate(string email, string pw, bool spoofDeviceId)
        {
            byte[] passwordHash, deviceHash;

            using (SHA512CryptoServiceProvider sha512 = new SHA512CryptoServiceProvider())
            {
                byte[] bytePassword = Encoding.UTF8.GetBytes(pw);
                passwordHash = sha512.ComputeHash(bytePassword);
            }

            if (!spoofDeviceId)
                deviceHash = GetDeviceId();
            else
            {
                using (SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider())
                {
                    byte[] byteEmail = Encoding.UTF8.GetBytes(email);
                    deviceHash = sha256.ComputeHash(byteEmail);
                }
            }

            using (HttpClient client = new HttpClient())
            {
                int time = DateTime.UtcNow.Millisecond;

                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                client.DefaultRequestHeaders.Add("Origin", "https://www.nexon.com");
                client.DefaultRequestHeaders.Referrer = new Uri($"https://www.nexon.com/account/en/login?ts={time}");
                client.DefaultRequestHeaders.AcceptEncoding.ParseAdd("gzip, deflate");
                client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US");

                string jsonContent = await Task.Factory.StartNew(() =>
                {
                    return JsonConvert.SerializeObject(new
                    {
                        id = email,
                        password = string.Concat(passwordHash.Select(b => b.ToString("X2"))).ToLower(),
                        client_id = "7853644408", // Static
                        device_id = string.Concat(deviceHash.Select(b => b.ToString("X2"))).ToLower(), //Might be a better idea to spoof the device_id
                        scope = "us.launcher.all",
                        auto_login = false
                    });
                });

                StringContent content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                HttpResponseMessage response = await client.PostAsync(LoginUri, content).ConfigureAwait(false);
                string responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if(response.IsSuccessStatusCode)
                {
                    var result = JsonConvert.DeserializeAnonymousType(responseContent, new
                    {
                        id_token = "",
                        access_token = "",
                        user_no = 0,
                        hashed_user_no = "",
                        id_token_expires_in = default(uint),
                        access_token_expires_in = default(uint),
                        is_verified = default(bool),
                        country_code = ""
                    });

                    IdentityToken = new NexonToken(result.id_token, result.id_token_expires_in);
                    AccessToken = new NexonToken(result.access_token, result.access_token_expires_in);
                }
                else
                {
                    var error = JsonConvert.DeserializeAnonymousType(responseContent, new
                    {
                        code = "",
                        message = "",
                        description = ""
                    });

                    throw new WebAuthenticationException(error.code, error.message);
                }
            }
        }

        /// <summary>
        /// Accesses the API resource and returns the result of the request.
        /// </summary>
        /// <typeparam name="TResult">The (anonymous) result type.</typeparam>
        /// <param name="resource">The resource to be accessed.</param>
        /// <param name="result">The result of the request.</param>
        /// <returns></returns>
        private async Task<TResult> AccessApiResource<TResult>(Uri resource, TResult result)
        {
            if (AccessToken == null || AccessToken.IsUpdateRequired)
                throw new WebAuthenticationException(WebAuthenticationErrorCodes.InvalidAccessToken, "Access token is invalid or outdated.");

            var filter = new HttpClientHandler();
            using (var client = new HttpClient(filter))
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", Convert.ToBase64String(Encoding.UTF8.GetBytes(AccessToken.Value)));
                filter.CookieContainer.Add(HomeUri, new Cookie("nxtk", AccessToken.Value));

                try
                {
                    string response = await client.GetStringAsync(resource).ConfigureAwait(false);

                    return JsonConvert.DeserializeAnonymousType(response, result);
                }
                catch (HttpRequestException hEx)
                {
                    throw new WebAuthenticationException(WebAuthenticationErrorCodes.HttpError, hEx.Message, hEx);
                }
            }
        }

        /// <summary>
        /// Obtains the Passport token by accessing the API with a valid identity and access token
        /// </summary>
        /// <returns>A valid Passport token</returns>
        /// <remarks>https://api.nexon.io/users/me/passport</remarks>
        private async Task<NexonPassport> GetPassport()
        {
            var result = await AccessApiResource(PassportUri, new
            {
                user_no = 0,
                membership_no = 0,
                passport = "",
                auth_token = ""
            });

            return new NexonPassport(result.passport);
        }

        private async Task<string> GetTicket()
        {
            string json = await Task.Factory.StartNew(() =>
            {
                return JsonConvert.SerializeObject(new
                {
                    id_token = IdentityToken.Value,
                    product_id = "10100",
                    device_id = string.Concat(GetDeviceId().Select(b => b.ToString("X2"))).ToLower()
                });
            });

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", AccessToken.Value);

                StringContent content = new StringContent(json, Encoding.UTF8, "application/json");

                HttpResponseMessage response = await client.PostAsync(TicketUri, content).ConfigureAwait(false);
                string responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if(response.IsSuccessStatusCode)
                {
                    var result = JsonConvert.DeserializeAnonymousType(responseContent, new
                    {
                        ticket = "",
                    });

                    return result.ticket;
                }
                else
                {
                    throw new WebAuthenticationException(WebAuthenticationErrorCodes.HttpError, "Failed to obtain ticket");
                }
            }
        }

        /// <summary>
        /// Generates the unique Device Identifier for this machine
        /// </summary>
        /// <returns></returns>
        private byte[] GetDeviceId()
        {
            RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32);
            RegistryKey specificKey = key.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography", false);

            string machineGuid = (string)specificKey.GetValue("MachineGuid", string.Empty);
            string wmicUuid = string.Empty;

            try
            {
                ProcessStartInfo info = new ProcessStartInfo(@"C:\Windows\System32\cmd.exe", "/c wmic csproduct get uuid");
                info.CreateNoWindow = true;
                info.RedirectStandardInput = true;
                info.RedirectStandardOutput = true;
                info.UseShellExecute = false;

                Process p = new Process();
                p.StartInfo = info;
                p.Start();

                while (!p.StandardOutput.EndOfStream)
                {
                    string s = p.StandardOutput.ReadLine().TrimEnd(' ');

                    if (Regex.IsMatch(s, @"\b\w+-\w+-\w+-\w+-\w+\b"))
                        wmicUuid = s;
                }
            }
            catch (Exception)
            {
                //TODO: Handle errors
            }

            using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
            {
                string plainText = string.Concat(wmicUuid, machineGuid);
                byte[] bytes = Encoding.UTF8.GetBytes(plainText);

                return sha.ComputeHash(bytes);
            }
        }
    }
}

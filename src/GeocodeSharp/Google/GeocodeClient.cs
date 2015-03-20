using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace GeocodeSharp.Google
{
    public class GeocodeClient : IGeocodeClient
    {
        private readonly string _cryptoKey;
        private readonly string _baseUrl;
        private const string GoogleMapsGeocodeJsonEndpoint = "http://maps.googleapis.com/maps/api/geocode/json";

        /// <summary>
        /// Initialize GeocodeClient without a Google API key and use default annonymouse access.
        /// NOTE: Throttling may apply.
        /// </summary>
        public GeocodeClient()
            : this(null) { }

        /// <summary>
        /// Initialize GeocodeClient with your Google API key to utilize it in the requests to Google and bypass the default annonymous throttling.
        /// </summary>
        /// <param name="apiKey">Google Maps API Key</param>
        public GeocodeClient(string apiKey)
            : this(null, null, null) { }

        /// <summary>
        /// Initialize GeocodeClient with your Google API key to utilize it in the requests to Google and bypass the default annonymous throttling.
        /// </summary>
        /// <param name="apiKey">Google Maps API Key</param>
        /// <param name="clientId">The client id</param>
        /// <param name="cryptoKey">The signature key</param>
        public GeocodeClient(string clientId, string cryptoKey)
            : this(null, clientId, cryptoKey) { }

        /// <summary>
        /// Initialize GeocodeClient with your Google API key to utilize it in the requests to Google and bypass the default annonymous throttling.
        /// </summary>
        /// <param name="apiKey">Google Maps API Key</param>
        /// <param name="clientId">The client id</param>
        /// <param name="cryptoKey">The signature key</param>
        protected GeocodeClient(string apiKey, string clientId, string cryptoKey)
        {
            if (apiKey != null && (clientId != null || cryptoKey != null))
            {
                throw new ArgumentException("Either specify apiKey or clientId & cryptoKey");
            }

            _cryptoKey = cryptoKey;

            var queryStringValues = new List<string>();
            if (apiKey != null)
            {
                queryStringValues.Add(string.Format("key={0}", apiKey));
            }
            if (clientId != null)
            {
                queryStringValues.Add(string.Format("client={0}", clientId));
            }

            _baseUrl = queryStringValues.Any()
                ? string.Format("{0}?{1}&", GoogleMapsGeocodeJsonEndpoint, string.Join("&", queryStringValues))
                : GoogleMapsGeocodeJsonEndpoint;
        }

        public string GetSignature(string url)
        {
            var encoding = new ASCIIEncoding();

            var usablePrivateKey = _cryptoKey.Replace("-", "+").Replace("_", "/");
            var privateKeyBytes = Convert.FromBase64String(usablePrivateKey);

            var uri = new Uri(url);
            var encodedPathAndQueryBytes = encoding.GetBytes(uri.LocalPath + uri.Query);

            // compute the hash
            var algorithm = new HMACSHA1(privateKeyBytes);
            var hash = algorithm.ComputeHash(encodedPathAndQueryBytes);

            // convert the bytes to string and make url-safe by replacing '+' and '/' characters
            return Convert.ToBase64String(hash).Replace("+", "-").Replace("/", "_");
        }

        public async Task<GeocodeResponse> GeocodeAddress(string address, string region = null)
        {
            var url = BuildUrl(address, region);

            string json;
            var request = WebRequest.CreateHttp(url);
            using (var ms = new MemoryStream())
            {
                using (var response = await request.GetResponseAsync())
                using (var body = response.GetResponseStream())
                {
                    if (body != null) await body.CopyToAsync(ms);
                }

                json = Encoding.UTF8.GetString(ms.ToArray());
            }
            return JsonConvert.DeserializeObject<GeocodeResponse>(json);
        }

        private string BuildUrl(string address, string region)
        {
            if (address == null) throw new ArgumentNullException("address");

            var buildUrl = string.Concat(_baseUrl, string.IsNullOrWhiteSpace(region)
                ? string.Format("address={0}", Uri.EscapeDataString(address))
                : string.Format("address={0}&region={1}", Uri.EscapeDataString(address), Uri.EscapeDataString(region)));

            if (_cryptoKey == null)
                return buildUrl;

            var signature = GetSignature(buildUrl);

            buildUrl = string.Concat(buildUrl,
                string.Format("&signature={0}", signature));

            return buildUrl;
        }
    }
}

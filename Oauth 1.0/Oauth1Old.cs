using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Oauth_1._0
{
    internal class Oauth1Old
    {
        public string PrivateKeyContent { get; set; }
        public string Url { get; set; }
        public string ConsumerKey { get; set; }
        public string Token { get; set; }

        public Oauth1Old(string privateKeyContent, string url, string consumerKey, string token)
        {
            PrivateKeyContent = privateKeyContent;
            Url = url;
            ConsumerKey = consumerKey;
            Token = token;
        }
        public string RequestOath1()
        {
            string strOriginalUrl = Url;
            try
            {
                string strFormattedUrl = FormatCorrectUrl(strOriginalUrl);
                string signatureMethod = "RSA-SHA1";
                string strHttpMethod = "GET";
                string strConsumerKey = ConsumerKey;
                string strToken = Token;

                AuthorizeHeader authorizationHeader = GetRequestTokenAuthorizationHeader(strFormattedUrl, signatureMethod, strHttpMethod, strConsumerKey, "", strToken);
                string response = MakeRESTRequest(strFormattedUrl, authorizationHeader);
                return response;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string MakeRESTRequest(string strUrl, AuthorizeHeader objAuthorizationHeader)
        {
            string strResponseResult = string.Empty;
            try
            {
                string strNormalizedEndpoint = NormalizeUrl(strUrl);
                HttpWebRequest requestObject = (HttpWebRequest)WebRequest.Create(strNormalizedEndpoint);
                string strAuthorizationHeader = string.Empty;
                if (objAuthorizationHeader != null)
                {
                    strAuthorizationHeader = objAuthorizationHeader.ToString();
                }
                requestObject.Headers.Add("Authorization", strAuthorizationHeader);
                //string strProxy = "http://proxy.abcd.com:8080";
                //WebProxy proxyObject = new WebProxy(strProxy, true);
                //proxyObject.BypassProxyOnLocal = false;
                //proxyObject.Credentials = CredentialCache.DefaultCredentials;
                //requestObject.Proxy = proxyObject; 
                requestObject.Timeout = 12000;
                Stream objStream = requestObject.GetResponse().GetResponseStream();
                StreamReader objReader = new StreamReader(objStream);

                string strResLine = string.Empty;
                int i = 0;
                while (strResLine != null)
                {
                    i++;
                    strResLine = objReader.ReadLine();
                    if (strResLine != null) { strResponseResult += strResLine; }
                }
                return strResponseResult;
            }
            catch (WebException e)
            {
                throw e;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        AuthorizeHeader GetRequestTokenAuthorizationHeader(string strUrl, string signatureMethod, string httpMethod, string consumerKey, string strRealm, string token)
        {
            try
            {
                List<QueryParameter> searchParameters = ExtractQueryStrings(strUrl);
                searchParameters.Sort(new LexicographicComparer());
                string strTimeStamp = GenerateTimeStamp();
                string strNounce = GenerateNonce(strTimeStamp);
                List<QueryParameter> oauthParameters = new List<QueryParameter>();

                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.ConsumerKey.GetStringValue(), consumerKey));
                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.Token.GetStringValue(), token));
                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.SignatureMethod.GetStringValue(), signatureMethod));
                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.Timestamp.GetStringValue(), strTimeStamp));
                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.Nounce.GetStringValue(), strNounce));
                oauthParameters.Add(new QueryParameter(OAuthProtocolParameter.Version.GetStringValue(), "1.0"));

                oauthParameters.Sort(new LexicographicComparer());

                List<QueryParameter> MasterParameterList = new List<QueryParameter>();
                MasterParameterList.AddRange(searchParameters); MasterParameterList.AddRange(oauthParameters);
                string strSignatureBaseString = GenerateSignatureBaseString(strUrl, httpMethod, MasterParameterList);
                string strOauth_Signature = GenerateSignature(strSignatureBaseString);
                AuthorizeHeader authHeader = new AuthorizeHeader(strRealm, consumerKey, signatureMethod, strOauth_Signature, strTimeStamp, strNounce, "1.0", token);
                return authHeader;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string GenerateSignatureBaseString(string strUrl, string strHttpMethod, List<QueryParameter> protocolParameters)
        {
            StringBuilder sbSignatureBase = new StringBuilder();
            try
            {
                Uri uri = new Uri(strUrl);
                string strNormalizedUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);
                if (!((uri.Scheme == "http" && uri.Port == 80) || (uri.Scheme == "https" && uri.Port == 443)))
                    strNormalizedUrl += ":" + uri.Port;
                strNormalizedUrl += uri.AbsolutePath;

                string strNormalizedRequestParameters = NormalizeProtocolParameters(protocolParameters);
                sbSignatureBase.AppendFormat("{0}&", strHttpMethod);
                sbSignatureBase.AppendFormat("{0}&", UrlEncode(strNormalizedUrl));
                sbSignatureBase.AppendFormat("{0}", UrlEncode(strNormalizedRequestParameters));
                return sbSignatureBase.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string GenerateSignature(string strSignatureBaseString)
        {            
            SHA1Managed shaHASHObject = null;
            try
            {
                var privateKeyContent = PrivateKeyContent;
                var privateKey = privateKeyContent.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty);
                var rsa = RSA.Create();
                var privateKeyBytes = Convert.FromBase64String(privateKey);
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out int _);            
                               
                RSACryptoServiceProvider RSAcrypt = new();
                RSAcrypt.ImportPkcs8PrivateKey(privateKeyBytes, out int _);
                shaHASHObject = new SHA1Managed();
                byte[] data = Encoding.ASCII.GetBytes(strSignatureBaseString);
                byte[] hash = shaHASHObject.ComputeHash(data);
                byte[] rsaSignature = RSAcrypt.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
                string base64string = Convert.ToBase64String(rsaSignature);
                return UrlEncode(base64string);
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                if (shaHASHObject != null)
                {
                    shaHASHObject.Dispose();
                }
            }
        }       
        string GenerateNonce(string strTimeStamp)
        {
            try
            {
                Random random = new Random();
                Int64 randomNumber = random.Next(0, 100000000);
                return strTimeStamp.ToString() + randomNumber.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string GenerateTimeStamp()
        {
            try
            {
                TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1);
                return Math.Truncate(ts.TotalSeconds).ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string FormatCorrectUrl(string strUrl)
        {
            StringBuilder result = null;
            try
            {
                int questionIndex = strUrl.IndexOf('?');
                if (questionIndex == -1)
                {
                    return strUrl;
                }
                var parameters = strUrl.Substring(questionIndex + 1);
                result = new StringBuilder();
                result.Append(strUrl.Substring(0, questionIndex + 1));
                bool hasQueryParameters = false;
                if (!String.IsNullOrEmpty(parameters))
                {
                    string[] parts = parameters.Split('&');
                    hasQueryParameters = parts.Length > 0;
                    foreach (var part in parts)
                    {
                        var nameValue = part.Split('=');
                        if (!nameValue[0].Equals(string.Empty))
                        {
                            result.Append(nameValue[0] + "=");
                        }
                        if (nameValue.Length == 2)
                        {
                            result.Append(UrlEncode(nameValue[1]));
                            result.Append("&");
                        }
                    }
                    if (hasQueryParameters)
                    {
                        result = result.Remove(result.Length - 1, 1);
                    }
                }
                return result.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string UrlEncode(string strValue)
        {
            string reservedCharacters = " !*'();:@&=+$,/?%#[]";
            try
            {
                if (String.IsNullOrEmpty(strValue))
                    return String.Empty;
                StringBuilder sbResult = new StringBuilder();

                foreach (char @char in strValue)
                {
                    if (reservedCharacters.IndexOf(@char) == -1)
                        sbResult.Append(@char.ToString());
                    else
                    {
                        sbResult.AppendFormat("%{0:X2}", (int)@char);
                    }
                }
                return sbResult.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string NormalizeUrl(string strUrl)
        {
            StringBuilder result = null;
            try
            {
                int questionIndex = strUrl.IndexOf('?');
                if (questionIndex == -1)
                {
                    return strUrl;
                }
                var parameters = strUrl.Substring(questionIndex + 1);
                result = new StringBuilder();
                result.Append(strUrl.Substring(0, questionIndex + 1));
                bool hasQueryParameters = false;
                if (!String.IsNullOrEmpty(parameters))
                {
                    string[] parts = parameters.Split('&');
                    hasQueryParameters = parts.Length > 0;
                    foreach (var part in parts)
                    {
                        var nameValue = part.Split('=');
                        result.Append(nameValue[0] + "=");
                        if (nameValue.Length == 2)
                        {
                            result.Append(nameValue[1]);
                        }
                        result.Append("&");
                    }
                    if (hasQueryParameters)
                    {
                        result = result.Remove(result.Length - 1, 1);
                    }
                }
                return result.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        string NormalizeProtocolParameters(IList<QueryParameter> parameters)
        {
            try
            {
                StringBuilder sbResult = new StringBuilder();
                QueryParameter p = null;
                for (int i = 0; i < parameters.Count; i++)
                {
                    p = parameters[i];
                    sbResult.AppendFormat("{0}={1}", p.Name, p.Value);
                    if (i < parameters.Count - 1)
                    {
                        sbResult.Append("&");
                    }
                }
                return sbResult.ToString();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        List<QueryParameter> ExtractQueryStrings(string strUrl)
        {
            try
            {
                int questionIndex = strUrl.IndexOf('?');
                if (questionIndex == -1)
                    return new List<QueryParameter>();
                string strParameters = strUrl.Substring(questionIndex + 1);
                var result = new List<QueryParameter>();

                if (!String.IsNullOrEmpty(strParameters))
                {
                    string[] parts = strParameters.Split('&');
                    foreach (string part in parts)
                    {
                        if (!string.IsNullOrEmpty(part) && !part.StartsWith("oauth_"))
                        {
                            if (part.IndexOf('=') != -1)
                            {
                                string[] nameValue = part.Split('=');
                                result.Add(new QueryParameter(nameValue[0], nameValue[1]));

                            }
                            else
                                result.Add(new QueryParameter(part, String.Empty));
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }        
    }
    public class AuthorizeHeader
    {
        public string Realm { get; private set; }
        public string ConsumerKey { get; private set; }
        public string SignatureMethod { get; private set; }
        public string Signature { get; private set; }
        public string Timestamp { get; private set; }
        public string Nounce { get; private set; }
        public string Version { get; private set; }
        public string BodyHash { get; private set; }
        public string Callback { get; private set; }
        public string Token { get; private set; }
        public string Verifier { get; private set; }
        public AuthorizeHeader(string realm, string consumerKey, string signatureMethod, string signature, string timestamp, string nounce, string version, string token)

        {
            Realm = realm;
            ConsumerKey = consumerKey;
            SignatureMethod = signatureMethod;
            Signature = signature;
            Timestamp = timestamp;
            Nounce = nounce;
            Version = version;
            Token = token;
            BodyHash = null;
        }
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("OAuth ");
            sb.AppendFormat("realm=\"{0}\", ", Realm);
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.ConsumerKey.GetStringValue(), ConsumerKey); // Mandetory Input
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.Token.GetStringValue(), Token);
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.SignatureMethod.GetStringValue(), SignatureMethod); // Mandetory Input
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.Timestamp.GetStringValue(), Timestamp); // Mandetory Input
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.Nounce.GetStringValue(), Nounce); // Mandetory Input            
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.Version.GetStringValue(), Version);            
            sb.AppendFormat("{0}=\"{1}\", ", OAuthProtocolParameter.Signature.GetStringValue(), Signature);
            
            sb = sb.Remove(sb.Length - 2, 2);
            return sb.ToString();
        }
    }
    public class EnumStringValueAttribute : Attribute
    {
        public string Value { get; private set; }
        public EnumStringValueAttribute(string value)
        {
            Value = value;
        }
    }
    public class QueryParameter
    {
        public string Name { get; private set; }
        public string Value { get; private set; }
        public QueryParameter(string name, string value)
        {
            Name = name;
            Value = value;
        }
    }
    public class LexicographicComparer : IComparer<QueryParameter>
    {
        public int Compare(QueryParameter x, QueryParameter y)
        {
            if (x.Name == y.Name)
                return string.Compare(x.Value, y.Value);
            else
                return string.Compare(x.Name, y.Name);

        }
    }
    internal enum OAuthProtocolParameter
    {
        [EnumStringValueAttribute("oauth_consumer_key")]
        ConsumerKey,
        [EnumStringValueAttribute("oauth_signature_method")]
        SignatureMethod,
        [EnumStringValueAttribute("oauth_signature")]
        Signature,
        [EnumStringValueAttribute("oauth_timestamp")]
        Timestamp,
        [EnumStringValueAttribute("oauth_nonce")]
        Nounce,
        [EnumStringValueAttribute("oauth_version")]
        Version,
        [EnumStringValueAttribute("oauth_callback")]
        Callback,
        [EnumStringValueAttribute("oauth_verifier")]
        Verifier,
        [EnumStringValueAttribute("oauth_token")]
        Token,
        [EnumStringValueAttribute("oauth_token_secret")]
        TokenSecret,
        [EnumStringValueAttribute("oauth_body_hash")]
        BodHash

    }
    public static class EnumStringValueExtension
    {
        public static string GetStringValue(this Enum value)
        {
            string output = null;
            Type type = value.GetType();
            FieldInfo fieldInfo = type.GetField(value.ToString());
            EnumStringValueAttribute[] attributes = fieldInfo.GetCustomAttributes(typeof(EnumStringValueAttribute), false) as EnumStringValueAttribute[];
            if (attributes.Length > 0)
                output = attributes[0].Value;
            return output;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPals
{
    // Fluent interface voor het versturen van requests
    public class RequestBuilder
    {
        public const string BaseUrl = "http://localhost:9000/";

        private TimeSpan _requestTimeout;
        private readonly HttpRequestMessage _requestMessage;

        public RequestBuilder(HttpMethod method, string url) {
            _requestMessage = new HttpRequestMessage(method, url);
            _requestMessage.Headers.Add("Accept", ContentType.ApplicationJson.ContentTypeToString());
            _requestTimeout = new TimeSpan(0, 1, 0);
        }

        public virtual RequestBuilder WithTextContent(string requestContent) {
            SetContent(requestContent, ContentType.TextPlain);
            return this;
        }

        private void SetContent(string requestContent, ContentType contentType) {
            _requestMessage.Content = new StringContent(requestContent, Encoding.UTF8, contentType.ContentTypeToString());
        }

        public virtual bool SendBool() {
            var content = SendRequest(_requestMessage, _requestTimeout);
            return content != null;
        }

        public virtual string SendString() {
            return SendRequest(_requestMessage, _requestTimeout);
        }

        private string SendRequest(HttpRequestMessage message, TimeSpan requestTimeout) {
            using (var request = message) {
                using (var client = new HttpClient { Timeout = requestTimeout }) {
                    var response = client.SendAsync(request);
                    return InterpretResponse(response);
                }
            }
        }

        private string InterpretResponse(Task<HttpResponseMessage> response) {
            var responseContent = response.Result.Content.ReadAsStringAsync().Result;

            if (response.Result.IsSuccessStatusCode) {
                return responseContent;
            }
            return null;
        }

        public static RequestBuilder Get(string url) {
            return new RequestBuilder(HttpMethod.Get, BaseUrl + url);
        }
        public static RequestBuilder Post(string url) {
            return new RequestBuilder(HttpMethod.Post, BaseUrl + url);
        }
    }

    internal enum ContentType
    {
        ApplicationJson,
        TextPlain
    }

    internal static class ContentTypeExtensions
    {
        public static string ContentTypeToString(this ContentType type) {
            switch (type) {
            case ContentType.ApplicationJson:
                return "application/json";
            case ContentType.TextPlain:
                return "text/plain";
            default:
                return "";
            }
        }
    }
}

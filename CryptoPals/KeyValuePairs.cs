using System;
using System.Collections.Generic;

namespace CryptoPals
{
    class KeyValuePairs
    {
        private static int counter = 0;

        public Dictionary<string, string> Dictionary { get; private set; }

        public string this[string key] {
            get { return this.Dictionary[key]; }
            set { this.Dictionary.Add(key, this.ValidateValue(value)); }
        }

        public KeyValuePairs() {
            this.Dictionary = new Dictionary<string, string>();
        }

        public string ValidateValue(string value) {
            return value.Replace("&", "").Replace("=", "");
        }

        public void Print() {
            // Print the object (the key value pairs) in a pretty way
            Console.WriteLine("{");
            foreach (var kv in this.Dictionary)
                Console.WriteLine(kv.Key + ": " + kv.Value + ",");
            Console.WriteLine("}");
        }

        public string ToUrl() {
            string result = "";
            foreach (var kv in this.Dictionary) {
                if (result != "")
                    result += '&';
                result += kv.Key + '=' + kv.Value;
            }
            return result;
        }

        public static KeyValuePairs FromURL(string url) {
            KeyValuePairs result = new KeyValuePairs();
            string[] kvs = url.Split('&');
            foreach (string kv in kvs) {
                string[] split = kv.Split('=');
                if (split.Length != 2)
                    throw new Exception("Each key value pair should be of the form key=value. This string is not [" + kv + "]");
                result[split[0]] = split[1];
            }
            return result;
        }

        public static KeyValuePairs ProfileFor(string email) {
            KeyValuePairs result = new KeyValuePairs();
            result["email"] = email;
            result["uid"] = counter++.ToString();
            result["role"] = "user";
            return result;
        }
    }
}

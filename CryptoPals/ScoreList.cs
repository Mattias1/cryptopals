using System;

namespace CryptoPals
{
    class ScoreItem
    {
        // Members
        public byte[] Source;
        public double Score;
        public byte[] KeyUsed;

        // Properties
        public int KeyUsedInt {
            get { return BitConverter.ToInt32(this.KeyUsed, 0); }
            set { this.KeyUsed = BitConverter.GetBytes(value); }
        }

        public string Base64String {
            get { return Convert.ToBase64String(this.Source); }
        }
        public string HexString {
            get { return Helpers.ToHexString(this.Source); }
        }
        public string UTF8String {
            get { return Helpers.ToUTF8String(this.Source); }
        }

        // Methods for automatic frequency analysis
        /// <summary>
        /// Do a frequency analysis of this particular raw string
        /// </summary>
        /// <param name="raw">A byte array that (if correctly) encoded with UTF-8</param>
        /// <param name="keyUsed">The key used to create this input</param>
        /// <returns></returns>
        public static ScoreItem DoFrequencyAnalysis(byte[] raw, byte[] keyUsed) {
            ScoreItem current = new ScoreItem(raw);
            current.Score = ScoreItem.FrequencyScore(current.UTF8String);
            current.KeyUsed = keyUsed;
            return current;
        }
        /// <summary>
        /// Do a frequancy analysis of this particular raw string
        /// </summary>
        /// <param name="raw">A byte array that (if correctly) encoded with UTF-8</param>
        /// <param name="keyUsed">The key used to create this input</param>
        /// <param name="scoreList">The scorelist this result gets stored in (if promising)</param>
        /// <returns></returns>
        public static ScoreItem InsertFrequencyAnalysis(byte[] raw, byte[] keyUsed, ScoreItem[] scoreList) {
            ScoreItem current = DoFrequencyAnalysis(raw, keyUsed);
            current.InsertInScoreList(scoreList);
            return current;
        }

        // Methods that are used for the frequancy analysis. If you want, you can use them manually.
        public ScoreItem(byte[] source) {
            this.Source = source;
        }

        /// <summary>
        /// Inserts this possible plaintext in the top N possible plaintexts (assumes that the score is set).
        /// </summary>
        /// <param name="scoreList"></param>
        /// <returns>True if it is in the top N, false otherwise</returns>
        public bool InsertInScoreList(ScoreItem[] scoreList) {
            // If it's not a record, return false
            if (scoreList[scoreList.Length - 1] != null && this.Score >= scoreList[scoreList.Length - 1].Score)
                return false;

            // So now we know it is a new best score, insert it in the right place
            scoreList[scoreList.Length - 1] = this;
            for (int i = scoreList.Length - 2; i >= 0; i--) {
                if (scoreList[i] == null || this.Score < scoreList[i].Score) {
                    scoreList[i + 1] = scoreList[i];
                    scoreList[i] = this;
                }
                else break;
            }
            return true;
        }

        /// <summary>
        /// Display this score item
        /// </summary>
        /// <param name="displaySource">Whether or not to display the source array (as a UTF-8 string)</param>
        /// <returns></returns>
        public string ToString(bool displaySource) {
            return (displaySource ? ("Source: " + this.UTF8String + ", ") : "") + "Key: " + Helpers.ToHexString(this.KeyUsed, true) + ", Score: " + this.Score.ToString();
        }
        public override string ToString() {
            return this.ToString(true);
        }

        /// <summary>
        /// Calculate a score as to how close it is to the 'perfect english text'
        /// The lower the score, the closer
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static double FrequencyScore(string s) {
            // The frequencies of english text (%)
            double[] frequencies_en = {
                8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,                   // a - g
                6.094, 6.966, .153, .772, 4.025, 2.406, 6.749, 7.507, 1.929,        // h - p
                .095, 5.987, 6.327, 9.056, 2.758, .978, 2.360, .150, 1.974, .074,   // q - z
                20, 0                                                               // Space, Other characters (assume they don't occur)
            };

            // Count the occurances of every letter
            s = s.ToLower();
            double[] counts = new double[frequencies_en.Length];
            for (int i = 0; i < s.Length; i++) {
                if ('a' <= s[i] && s[i] <= 'z')
                    counts[s[i] - 'a']++;
                else if (s[i] == ' ')
                    counts[26]++;
                else
                    counts[counts.Length - 1]++;
            }

            // Calculate a single score, by giving more penalty the further away our counted score is to the optimal frequency.
            double normalizeFactor = 100 / s.Length;
            double score = 0;
            for (int i = 0; i < counts.Length; i++)
                score += Math.Abs(frequencies_en[i] - counts[i] * normalizeFactor);
            return score;
        }

        /// <summary>
        /// Write the scorelist to the console
        /// </summary>
        /// <param name="scoreList"></param>
        /// <param name="displaySource"></param>
        public static void DisplayScoreList(ScoreItem[] scoreList, bool displaySource = true) {
            for (int i = 0; i < scoreList.Length; i++) {
                Console.WriteLine(i.ToString() + ". " + scoreList[i].ToString(displaySource));
            }
        }
    }
}

using System;

namespace CryptoPals
{
    class PossiblePlaintext
    {
        // Members
        public byte[] Source;
        public double Score;

        // Properties
        public string Base64String {
            get { return Convert.ToBase64String(this.Source); }
        }
        public string HexString {
            get { return Helpers.ToHexString(this.Source); }
        }
        public string UTF8String {
            get { return Helpers.ToUTF8String(this.Source); }
        }

        // Methods
        public PossiblePlaintext(byte[] source) {
            this.Source = source;
        }

        /// <summary>
        /// Inserts this possible plaintext in the top N possible plaintexts.
        /// </summary>
        /// <param name="scoreList"></param>
        /// <returns>True if it is in the top N, false otherwise</returns>
        public bool InsertInScoreList(PossiblePlaintext[] scoreList) {
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
    }
}

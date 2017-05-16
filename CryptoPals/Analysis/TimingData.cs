using System.Linq;

namespace CryptoPals
{
    // Made for challenge 31 and 32 (set 4)
    public class TimingData
    {
        public int NrOfTriesPerByte { get; private set; }
        double[][] _times;

        public TimingData(int nrOfTriesPerByte) {
            NrOfTriesPerByte = nrOfTriesPerByte;
            _times = new int[256].Select(_ => new double[nrOfTriesPerByte]).ToArray();
        }

        public void AddData(int key, int nrOfTry, double time) {
            _times[key][nrOfTry] = time;
        }

        public double AverageTime(int key, int skip = 2) {
            return _times[key].OrderByDescending(t => t).Skip(skip).Average();
        }

        public double[] GetRaw(int key) => _times[key];
    }
}

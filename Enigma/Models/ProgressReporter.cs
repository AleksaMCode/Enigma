using System;

namespace Enigma.Models
{
    public class ProgressReporter
    {
        private Action<string> LogInfo { get; set; }

        private Action<int> PercentageDone { get; set; }

        public ProgressReporter(Action<string> log, Action<int> percentage)
        {
            LogInfo = log;
            PercentageDone = percentage;
        }

        public void Log(string line)
        {
            LogInfo?.Invoke(line);
        }

        public void SetPercentage(int i)
        {
            PercentageDone?.Invoke(i);
        }
    }
}

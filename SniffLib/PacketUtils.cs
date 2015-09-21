using System;

namespace SniffLib
{
    static class PacketUtils
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime FromUnixTime(uint seconds)
        {
            return Epoch.AddSeconds(seconds);
        }

        public static ulong UnixTimestamp(this DateTime date)
        {
            var timeSpan = (date - Epoch);
            return (ulong)timeSpan.TotalSeconds;
        }
    }
}

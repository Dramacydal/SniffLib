using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SniffLib
{
    public abstract class Sniff : IDisposable
    {
        protected BinaryReader reader = null;
        protected long DataOffset = 0;

        protected Sniff(BinaryReader reader)
        {
            this.reader = reader;
            ReadHeader();
        }

        public static Sniff Load(string file)
        {
            var reader = new BinaryReader(File.Open(file, FileMode.Open, FileAccess.Read));
            var fileHeader = reader.ReadBytes(3);
            if (Encoding.ASCII.GetString(fileHeader) == "PKT")
                return new SniffPkt(reader);
            else
            {
                reader.BaseStream.Position = 0;
                return new SniffRaw(reader);
            }

        }

        public void Dispose()
        {
            if (reader != null)
                reader.Close();
        }

        void Reset()
        {
            reader.BaseStream.Position = DataOffset;
        }

        protected abstract void ReadHeader();
        public abstract Packet NextPacket();

        public List<Packet> ReadAllPackets(Func<Packet, bool> filterPredicate = null)
        {
            Reset();

            var packets = new List<Packet>();

            while (reader.BaseStream.Position != reader.BaseStream.Length)
            {
                var packet = NextPacket();
                if (filterPredicate == null || filterPredicate(packet))
                    packets.Add(packet);
            }

            return packets;
        }
    }
}

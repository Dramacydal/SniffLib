using System;
using System.IO;

namespace SniffLib
{
    public class Packet
    {
        public enum PacketDirection
        {
            ClientToServer = 0,
            ServerToClient = 1,
        }

        public Packet(uint Opcode, PacketDirection Direction, byte[] Data, DateTime Time)
        {
            this.Opcode = Opcode;
            this.Direction = Direction;
            this.Data = Data;
            this.Time = Time;
        }

        public uint Opcode { get; private set; }
        public PacketDirection Direction { get; private set; }
        public byte[] Data { get; private set; }
        public DateTime Time { get; private set; }
        

        public byte[] ToRaw()
        {
            using (var writer = new BinaryWriter(new MemoryStream()))
            {
                var m = new MemoryStream();
                writer.Write((uint)Opcode);
                writer.Write((uint)Data.Length);
                writer.Write((uint)Time.UnixTimestamp());
                writer.Write((byte)Direction);
                writer.Write(Data);

                writer.BaseStream.Position = 0;
                var ret = new byte[writer.BaseStream.Length];
                var read = writer.BaseStream.Read(ret, 0, (int)writer.BaseStream.Length);
                if (read != ret.Length)
                    throw new Exception("read != size");

                return ret;
            }
        }
    }
}

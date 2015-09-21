using System.IO;

namespace SniffLib
{
    class SniffRaw : Sniff
    {
        public SniffRaw(BinaryReader reader) : base(reader) { }

        protected override void ReadHeader()
        {
            // nothing to do
            DataOffset = 0;
        }

        public override Packet NextPacket()
        {
            var opcode = reader.ReadUInt32();
            var length = reader.ReadInt32();
            var time = PacketUtils.FromUnixTime(reader.ReadUInt32());
            var direction = (Packet.PacketDirection)reader.ReadByte();
            var data = reader.ReadBytes(length);

            return new Packet(opcode, direction, data, time);
        }
    }
}

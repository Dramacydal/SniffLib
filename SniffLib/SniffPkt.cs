using System;
using System.IO;

namespace SniffLib
{
    class SniffPkt : Sniff
    {
        public PktVersion Version { get; protected set; }
        protected uint StartTickCount { get; private set; }
        protected DateTime StartTime { get; private set; }

        public SniffPkt(BinaryReader reader) : base(reader) { }

        protected override void ReadHeader()
        {
            Version = (PktVersion)reader.ReadUInt16();

            switch (Version)
            {
                case PktVersion.V2_1:
                {
                    reader.ReadUInt16();    // build
                    reader.ReadBytes(40);   // session key
                    break;
                }
                case PktVersion.V2_2:
                {
                    reader.ReadByte();      // sniffer id
                    reader.ReadUInt16();    // client build
                    reader.ReadBytes(4);    // client locale
                    reader.ReadBytes(20);   // packet key
                    reader.ReadBytes(64);   // realm name
                    break;
                }
                case PktVersion.V3_0:
                {
                    var snifferId = reader.ReadByte();  // sniffer id
                    reader.ReadUInt32();    // client build
                    reader.ReadBytes(4);    // client locale
                    reader.ReadBytes(40);   // session key
                    var additionalLength = reader.ReadInt32();
                    var preAdditionalPos = reader.BaseStream.Position;
                    reader.ReadBytes(additionalLength);
                    var postAdditionalPos = reader.BaseStream.Position;
                    if (snifferId == 10)    // xyla
                    {
                        reader.BaseStream.Position = preAdditionalPos;
                        StartTime = PacketUtils.FromUnixTime(reader.ReadUInt32());    // start time
                        StartTickCount = reader.ReadUInt32();     // start tick count
                        reader.BaseStream.Position = postAdditionalPos;
                    }
                    break;
                }
                case PktVersion.V3_1:
                {
                    reader.ReadByte();      // sniffer id
                    reader.ReadUInt32();    // client build
                    reader.ReadBytes(4);    // client locale
                    reader.ReadBytes(40);   // session key
                    StartTime = PacketUtils.FromUnixTime(reader.ReadUInt32());    // start time
                    StartTickCount = reader.ReadUInt32();     // start tick count
                    var additionalLength = reader.ReadInt32();
                    reader.ReadBytes(additionalLength);
                    break;
                }
                default:
                {
                    throw new Exception(string.Format("Unknown PKT version: {0}", Version));
                }
            }

            DataOffset = reader.BaseStream.Position;
        }

        public override Packet NextPacket()
        {
            Packet.PacketDirection direction;
            byte[] data;
            uint opcode;
            DateTime time;

            switch (Version)
            {
                case PktVersion.V2_1:
                case PktVersion.V2_2:
                {
                    direction = (reader.ReadByte() == 0xff) ? Packet.PacketDirection.ServerToClient : Packet.PacketDirection.ClientToServer;
                    time = PacketUtils.FromUnixTime(reader.ReadUInt32());
                    reader.ReadInt32(); // tick count
                    var length = reader.ReadInt32();

                    if (direction == Packet.PacketDirection.ServerToClient)
                    {
                        opcode = reader.ReadUInt16();
                        data = reader.ReadBytes(length - 2);
                    }
                    else
                    {
                        opcode = reader.ReadUInt32();
                        data = reader.ReadBytes(length - 4);
                    }
                    break;
                }
                case PktVersion.V3_0:
                case PktVersion.V3_1:
                {
                    direction = (reader.ReadUInt32() == 0x47534d53) ? Packet.PacketDirection.ServerToClient : Packet.PacketDirection.ClientToServer;

                    if (Version == PktVersion.V3_0)
                    {
                        time = PacketUtils.FromUnixTime(reader.ReadUInt32());
                        var tickCount = reader.ReadUInt32();
                        if (StartTickCount != 0)
                            time = StartTime.AddMilliseconds(tickCount - StartTickCount);
                    }
                    else
                    {
                        reader.ReadUInt32();
                        var tickCount = reader.ReadUInt32();
                        time = StartTime.AddMilliseconds(tickCount - StartTickCount);
                    }

                    int additionalSize = reader.ReadInt32();
                    var length = reader.ReadInt32();
                    reader.ReadBytes(additionalSize);
                    opcode = reader.ReadUInt32();
                    data = reader.ReadBytes(length - 4);
                    break;
                }
                default:
                {
                    opcode = reader.ReadUInt16();
                    var length = reader.ReadInt32();
                    direction = (Packet.PacketDirection)reader.ReadByte();
                    time = PacketUtils.FromUnixTime((uint)reader.ReadUInt64());
                    data = reader.ReadBytes(length);
                    break;
                }
            }

            return new Packet(opcode, direction, data, time);
        }
    }
}

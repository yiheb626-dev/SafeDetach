using System;
using System.Collections.Generic;
using System.IO;

namespace SafeDetach {
 // Only the initial USBMux control frames are assembled. Device traffic is never parsed.
 public sealed class MuxFirstFrame {
  readonly uint initial; readonly List<byte> bytes=new List<byte>();readonly SortedDictionary<int,byte[]> pending=new SortedDictionary<int,byte[]>();bool done;
  public MuxFirstFrame(uint sequence){initial=sequence;}
  public bool Done {get{return done;}}
  public byte[] Feed(uint sequence,byte[] part) {
   if(done)return null;uint distance=unchecked(sequence-initial);
   if(distance>65536||distance+part.Length>65536||pending.Count>=64)throw new InvalidDataException("Handshake bounds");int offset=(int)distance;byte[] previous;
   if(pending.TryGetValue(offset,out previous)&&!Equal(previous,part))throw new InvalidDataException("Conflicting retransmission");pending[offset]=part;
   int retained=bytes.Count;foreach(var value in pending.Values)retained+=value.Length;if(retained>131072)throw new InvalidDataException("Handshake memory bound");
   while(pending.Count>0){int position=0;byte[] value=null;foreach(var entry in pending){position=entry.Key;value=entry.Value;break;}if(position>bytes.Count)break;pending.Remove(position);
    int overlap=Math.Min(value.Length,bytes.Count-position);for(int i=0;i<overlap;i++)if(bytes[position+i]!=value[i])throw new InvalidDataException("Conflicting overlap");for(int i=overlap;i<value.Length;i++)bytes.Add(value[i]);}
   if(bytes.Count<16)return null;uint length=(uint)(bytes[0]|bytes[1]<<8|bytes[2]<<16|bytes[3]<<24);if(length<16||length>65536)throw new InvalidDataException("Invalid frame length");
   if(bytes.Count<length)return null;done=true;byte[] result=bytes.GetRange(0,(int)length).ToArray();bytes.Clear();pending.Clear();return result;
  }
  static bool Equal(byte[] a,byte[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 }
 public sealed class MuxFrame {
  public uint Version,Tag,Value;public bool Connect,Result;
  public static MuxFrame Parse(byte[] bytes) {
   if(bytes.Length<16||BitConverter.ToUInt32(bytes,0)!=bytes.Length)return null;uint version=BitConverter.ToUInt32(bytes,4),kind=BitConverter.ToUInt32(bytes,8),tag=BitConverter.ToUInt32(bytes,12);
   var result=new MuxFrame {Version=version,Tag=tag};
   if(version==0&&kind==2&&bytes.Length==24){result.Connect=true;result.Value=BitConverter.ToUInt32(bytes,16);return result;}
   if(version==0&&kind==1&&bytes.Length==20){result.Result=true;result.Value=BitConverter.ToUInt32(bytes,16);return result;}
   if(version!=1||kind!=8)return null;
   try {var body=new byte[bytes.Length-16];Buffer.BlockCopy(bytes,16,body,0,body.Length);var map=AppleServiceScanner.ParsePlist(body);object type,value;if(!map.TryGetValue("MessageType",out type))return null;string name=Convert.ToString(type);
    result.Connect=name=="Connect";result.Result=name=="Result";if(!result.Connect&&!result.Result)return null;if(!map.TryGetValue(result.Connect?"DeviceID":"Number",out value)||!(value is string)||!uint.TryParse((string)value,out result.Value))return null;return result;
   }catch(Exception ex){if(ex is System.Xml.XmlException||ex is InvalidDataException||ex is InvalidCastException||ex is ArgumentException||ex is OverflowException)return null;throw;}
  }
 }
 public sealed class MuxPacket {
  public int Port,PayloadOffset,PayloadLength;public bool Outgoing;public byte Flags;public uint Sequence;public byte[] Payload;
  static int U16(byte[] data,int offset){return data[offset]<<8|data[offset+1];}
  static uint U32(byte[] data,int offset){return (uint)(data[offset]<<24|data[offset+1]<<16|data[offset+2]<<8|data[offset+3]);}
  public static MuxPacket Parse(byte[] header,int captured,int link) {
   int ip=link==0||link==108?4:link==1?14:link==101?0:link==113?16:-1;if(ip<0||header.Length<ip+40||header[ip]>>4!=4||header[ip+9]!=6)return null;
   int ihl=(header[ip]&15)*4,total=U16(header,ip+2);if(ihl<20||total<ihl+20||ip+total>captured||(U16(header,ip+6)&0x3fff)!=0)return null;
   if(header[ip+12]!=127||header[ip+13]!=0||header[ip+14]!=0||header[ip+15]!=1||header[ip+16]!=127||header[ip+17]!=0||header[ip+18]!=0||header[ip+19]!=1)return null;
   int tcp=ip+ihl;if(header.Length<tcp+20)return null;int thl=(header[tcp+12]>>4)*4;if(thl<20||ihl+thl>total)return null;
   int source=U16(header,tcp),destination=U16(header,tcp+2);if(source!=27015&&destination!=27015)return null;
   return new MuxPacket {Port=destination==27015?source:destination,Outgoing=destination==27015,Sequence=U32(header,tcp+4),Flags=header[tcp+13],PayloadOffset=tcp+thl,PayloadLength=total-ihl-thl};
  }
 }
 public sealed class AppleClientIdentity {
  public int Pid;public long Started;public string Name;
  public bool Same(AppleClientIdentity other){return other!=null&&Pid==other.Pid&&Started==other.Started&&Started>0;}
 }
 public sealed class AppleConnectionMatch {
  public int Port;public uint DeviceId;public string Serial;public AppleClientIdentity Client;
 }
 public sealed class MuxSessionTracker {
  sealed class Flow {public uint Initial,Tag,Version,Device;public string Serial;public MuxFirstFrame Out,In;public AppleClientIdentity Client;public long Time;}
  readonly Dictionary<int,Flow> flows=new Dictionary<int,Flow>();
  readonly Dictionary<int,AppleConnectionMatch> matches=new Dictionary<int,AppleConnectionMatch>();
  public void Clear(){flows.Clear();matches.Clear();}
  public void Prune(long now,Func<int,AppleClientIdentity> owner){var remove=new List<int>();foreach(var item in flows)if(now-item.Value.Time>5000)remove.Add(item.Key);foreach(int port in remove)flows.Remove(port);remove.Clear();foreach(var item in matches)if(!item.Value.Client.Same(owner(item.Key)))remove.Add(item.Key);foreach(int port in remove)matches.Remove(port);}
  public List<AppleConnectionMatch> Matches(){return new List<AppleConnectionMatch>(matches.Values);}
  public bool NeedsPayload(MuxPacket p){Flow flow;return flows.TryGetValue(p.Port,out flow)&&(p.Outgoing?!flow.Out.Done:flow.In!=null&&!flow.In.Done);}
  public void Accept(MuxPacket packet,long now,Dictionary<uint,string> devices,Func<int,AppleClientIdentity> owner) {
   Flow flow;bool found=flows.TryGetValue(packet.Port,out flow);
   if(packet.Outgoing&&(packet.Flags&0x12)==2){if(found&&flow.Initial==packet.Sequence)return;flows.Remove(packet.Port);matches.Remove(packet.Port);if(flows.Count>=256)return;flows[packet.Port]=new Flow {Initial=packet.Sequence,Out=new MuxFirstFrame(unchecked(packet.Sequence+1)),Time=now};return;}
   if((packet.Flags&5)!=0){flows.Remove(packet.Port);matches.Remove(packet.Port);return;}
   if(!found)return;
   if(!packet.Outgoing&&(packet.Flags&0x12)==0x12){if(flow.In==null)flow.In=new MuxFirstFrame(unchecked(packet.Sequence+1));return;}
   if(packet.Payload==null||packet.Payload.Length==0)return;var stream=packet.Outgoing?flow.Out:flow.In;if(stream==null){flows.Remove(packet.Port);return;}
   byte[] complete;try{complete=stream.Feed(packet.Sequence,packet.Payload);}catch(InvalidDataException){flows.Remove(packet.Port);return;}if(complete==null)return;
   var frame=MuxFrame.Parse(complete);if(frame==null){flows.Remove(packet.Port);return;}
   if(packet.Outgoing){string serial;if(!frame.Connect||!devices.TryGetValue(frame.Value,out serial)){flows.Remove(packet.Port);return;}flow.Client=owner(packet.Port);if(flow.Client==null){flows.Remove(packet.Port);return;}flow.Tag=frame.Tag;flow.Version=frame.Version;flow.Device=frame.Value;flow.Serial=serial;}
   else {string serial;if(flow.Client!=null&&frame.Result&&frame.Value==0&&frame.Tag==flow.Tag&&frame.Version==flow.Version&&devices.TryGetValue(flow.Device,out serial)&&serial==flow.Serial&&flow.Client.Same(owner(packet.Port)))matches[packet.Port]=new AppleConnectionMatch {Port=packet.Port,DeviceId=flow.Device,Serial=serial,Client=flow.Client};flows.Remove(packet.Port);}
  }
 }
}

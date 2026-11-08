using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;
namespace SafeDetach {
 public static class AppleServiceScanner {
  public sealed class Connection {public int State,LocalPort,RemotePort,Pid;public uint LocalAddress,RemoteAddress;}
  [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table,ref int length,bool sort,int family,int tableClass,uint reserved);
  public static List<Connection> Connections() {
   int length=0;GetExtendedTcpTable(IntPtr.Zero,ref length,false,2,5,0);IntPtr buffer=Marshal.AllocHGlobal(length);
   try {uint status=GetExtendedTcpTable(buffer,ref length,false,2,5,0);for(int attempt=0;status==122&&attempt<3;attempt++){Marshal.FreeHGlobal(buffer);buffer=IntPtr.Zero;buffer=Marshal.AllocHGlobal(length);status=GetExtendedTcpTable(buffer,ref length,false,2,5,0);}if(status!=0)throw new System.ComponentModel.Win32Exception((int)status);int count=Marshal.ReadInt32(buffer);var rows=new List<Connection>();
    for(int i=0;i<count;i++){IntPtr p=IntPtr.Add(buffer,4+i*24);uint lp=(uint)Marshal.ReadInt32(p,8),rp=(uint)Marshal.ReadInt32(p,16);rows.Add(new Connection {State=Marshal.ReadInt32(p),LocalAddress=(uint)Marshal.ReadInt32(p,4),LocalPort=(int)((lp&255)<<8|((lp>>8)&255)),RemoteAddress=(uint)Marshal.ReadInt32(p,12),RemotePort=(int)((rp&255)<<8|((rp>>8)&255)),Pid=Marshal.ReadInt32(p,20)});}return rows;
   }finally{Marshal.FreeHGlobal(buffer);}
  }
  static bool Loopback(uint address){return IPAddress.IsLoopback(new IPAddress(address));}
  public static List<int> Clients(List<Connection> rows,int servicePid,int self) {
   var found=new HashSet<int>();bool listener=false;foreach(var r in rows)if(r.Pid==servicePid&&r.State==2&&r.LocalPort==27015&&Loopback(r.LocalAddress))listener=true;
   if(listener)foreach(var c in rows)if(c.State==5&&c.RemotePort==27015&&c.Pid>4&&c.Pid!=servicePid&&c.Pid!=self&&Loopback(c.LocalAddress)&&Loopback(c.RemoteAddress))foreach(var s in rows)if(s.Pid==servicePid&&s.State==5&&s.LocalAddress==c.RemoteAddress&&s.RemoteAddress==c.LocalAddress&&s.LocalPort==c.RemotePort&&s.RemotePort==c.LocalPort){found.Add(c.Pid);break;}
   return new List<int>(found);
  }
  static byte[] Read(Stream stream,int length){var result=new byte[length];int offset=0;while(offset<length){int n=stream.Read(result,offset,length-offset);if(n==0)throw new EndOfStreamException();offset+=n;}return result;}
  static object Plist(XmlNode node,int depth) {
   if(depth>16)throw new InvalidDataException("设备服务响应过深。");
   if(node.Name=="dict"){var map=new Dictionary<string,object>();var children=node.ChildNodes;for(int i=0;i<children.Count;i+=2){if(children[i].Name!="key"||i+1>=children.Count)throw new InvalidDataException("设备服务响应格式错误。");map.Add(children[i].InnerText,Plist(children[i+1],depth+1));}return map;}
   if(node.Name=="array"){var list=new List<object>();foreach(XmlNode child in node.ChildNodes)list.Add(Plist(child,depth+1));return list;}
   if(node.Name=="string"||node.Name=="integer")return node.InnerText;
   if(node.Name=="true"||node.Name=="false")return node.Name=="true";return null;
  }
  public static Dictionary<string,object> ParsePlist(byte[] data) {
   var document=new XmlDocument {XmlResolver=null};using(var reader=XmlReader.Create(new MemoryStream(data),new XmlReaderSettings {DtdProcessing=DtdProcessing.Ignore,XmlResolver=null,IgnoreWhitespace=true,IgnoreComments=true,MaxCharactersInDocument=1024*1024}))document.Load(reader);
   if(document.DocumentElement==null||document.DocumentElement.Name!="plist"||document.DocumentElement.FirstChild==null)throw new InvalidDataException("Apple 服务响应无效。");return (Dictionary<string,object>)Plist(document.DocumentElement.FirstChild,0);
  }
  public static Dictionary<uint,string> DeviceIdentities() {
   byte[] body=Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>MessageType</key><string>ListDevices</string><key>ProgName</key><string>SafeDetach</string><key>ClientVersionString</key><string>SafeDetach</string><key>kLibUSBMuxVersion</key><integer>3</integer></dict></plist>");
   using(var client=new TcpClient()){var pending=client.BeginConnect(IPAddress.Loopback,27015,null,null);using(pending.AsyncWaitHandle){if(!pending.AsyncWaitHandle.WaitOne(1500))throw new TimeoutException("Apple 服务查询超时。");client.EndConnect(pending);}client.ReceiveTimeout=1500;client.SendTimeout=1500;using(var stream=client.GetStream()){
    using(var packet=new MemoryStream())using(var writer=new BinaryWriter(packet)){writer.Write((uint)(16+body.Length));writer.Write(1u);writer.Write(8u);writer.Write(1u);writer.Write(body);byte[] bytes=packet.ToArray();stream.Write(bytes,0,bytes.Length);}
    byte[] header=Read(stream,16);uint size=BitConverter.ToUInt32(header,0);if(size<16||size>1024*1024||BitConverter.ToUInt32(header,4)!=1||BitConverter.ToUInt32(header,8)!=8||BitConverter.ToUInt32(header,12)!=1)throw new InvalidDataException("Apple 服务响应无效。");
    var root=ParsePlist(Read(stream,(int)size-16));object value;if(!root.TryGetValue("DeviceList",out value))throw new InvalidDataException("Apple 服务未返回设备清单。");var result=new Dictionary<uint,string>();foreach(var item in (List<object>)value){var entry=(Dictionary<string,object>)item;var props=(Dictionary<string,object>)entry["Properties"];object connection;if(!props.TryGetValue("ConnectionType",out connection)||Convert.ToString(connection)!="USB")continue;string serial=Normalize(Convert.ToString(props["SerialNumber"]));uint id=Convert.ToUInt32(entry["DeviceID"]);if(serial.Length==0||result.ContainsKey(id))throw new InvalidDataException("Apple 服务未提供唯一设备身份。");result.Add(id,serial);}return result;
   }}
  }
  public static List<string> DeviceSerials() {return new List<string>(new HashSet<string>(DeviceIdentities().Values));}
  public static string Normalize(string value){return value.Replace("-","").Trim().ToUpperInvariant();}
  public static bool MatchesSingle(List<string> serials,string selected){return serials.Count==1&&serials[0]==Normalize(selected);}
  public static int Run(string instance) {
   using(var monitor=new AppleConnectionMonitor()) {monitor.Start();System.Threading.Thread.Sleep(3000);foreach(string line in monitor.Scan(instance))Console.WriteLine(line);return 0;}
  }
 }
}

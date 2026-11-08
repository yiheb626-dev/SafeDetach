using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SafeDetach;

class AppleConnections {
 static void Check(bool condition,string message){if(!condition)throw new Exception(message);}
 static byte[] Frame(bool connect,uint value,uint tag,uint version) {
  using(var memory=new MemoryStream())using(var writer=new BinaryWriter(memory)) {
   byte[] body=version==0?BitConverter.GetBytes(value):Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>MessageType</key><string>"+(connect?"Connect":"Result")+"</string><key>"+(connect?"DeviceID":"Number")+"</key><integer>"+value+"</integer></dict></plist>");
   writer.Write((uint)(16+body.Length+(version==0&&connect?4:0)));writer.Write(version);writer.Write(version==1?8u:connect?2u:1u);writer.Write(tag);writer.Write(body);if(version==0&&connect)writer.Write(0u);return memory.ToArray();
  }
 }
 static byte[] Slice(byte[] b,int offset,int count){var result=new byte[count];Buffer.BlockCopy(b,offset,result,0,count);return result;}
 static MuxPacket Packet(bool outgoing,uint sequence,byte flags,byte[] data){return new MuxPacket {Port=50000,Outgoing=outgoing,Sequence=sequence,Flags=flags,Payload=data};}
 static void Handshake(MuxSessionTracker tracker,Dictionary<uint,string> devices,Func<int,AppleClientIdentity> owner,uint tag,uint replyTag,uint result) {
  tracker.Accept(Packet(true,100,2,null),1,devices,owner);tracker.Accept(Packet(false,200,0x12,null),2,devices,owner);
  byte[] request=Frame(true,8,tag,1),response=Frame(false,result,replyTag,1);
  tracker.Accept(Packet(true,117,0x10,Slice(request,16,request.Length-16)),3,devices,owner);
  tracker.Accept(Packet(true,101,0x10,Slice(request,0,16)),4,devices,owner);
  tracker.Accept(Packet(false,201,0x10,Slice(response,0,16)),5,devices,owner);
  tracker.Accept(Packet(false,217,0x10,Slice(response,16,response.Length-16)),6,devices,owner);
 }
 static void Unit() {
  foreach(uint version in new uint[]{0,1})foreach(bool connect in new[]{true,false}) {
   var bytes=Frame(connect,connect?8u:0u,77,version);var stream=new MuxFirstFrame(0xfffffff8);Check(stream.Feed(8,Slice(bytes,16,bytes.Length-16))==null,"Out of order fragment completed early");Check(stream.Feed(0xfffffff8,Slice(bytes,0,8))==null,"First fragment completed early");Check(stream.Feed(0xfffffff8,Slice(bytes,0,8))==null,"Retransmission completed early");var full=stream.Feed(0,Slice(bytes,8,8));var frame=MuxFrame.Parse(full);Check(frame!=null&&frame.Connect==connect&&frame.Tag==77&&frame.Value==(connect?8u:0u),"Protocol/sequence wrap reassembly");Check(stream.Feed(0xfffffff8,bytes)==null,"Completed frame was re-emitted");
  }
  var conflict=new MuxFirstFrame(1);conflict.Feed(1,new byte[4]);try{conflict.Feed(1,new byte[]{1,0,0,0});throw new Exception("Conflict accepted");}catch(InvalidDataException){}
  var device=new Dictionary<uint,string>{{8,"AAA"}};var identity=new AppleClientIdentity {Pid=1234,Started=100,Name="fixture"};Func<int,AppleClientIdentity> owner=delegate(int p){return identity;};
  var tracker=new MuxSessionTracker();tracker.Accept(Packet(true,101,0x10,Frame(true,8,77,1)),0,device,owner);Check(tracker.Matches().Count==0,"Existing flow without SYN assigned");
  Handshake(tracker,device,owner,77,78,0);Check(tracker.Matches().Count==0,"Wrong tag accepted");tracker.Clear();Handshake(tracker,device,owner,77,77,2);Check(tracker.Matches().Count==0,"Rejected connection accepted");tracker.Clear();Handshake(tracker,device,owner,77,77,0);Check(tracker.Matches().Count==1&&tracker.Matches()[0].Serial=="AAA","Successful connection not assigned");
  identity=new AppleClientIdentity {Pid=1234,Started=200,Name="reused"};tracker.Prune(7,owner);Check(tracker.Matches().Count==0,"PID reuse retained");
  Handshake(tracker,device,owner,77,77,0);tracker.Accept(Packet(false,400,1,null),8,device,owner);Check(tracker.Matches().Count==0,"FIN retained connection");Handshake(tracker,device,owner,77,77,0);tracker.Accept(Packet(true,500,2,null),9,device,owner);Check(tracker.Matches().Count==0,"Port reuse retained connection");
  tracker.Clear();Handshake(tracker,device,owner,77,77,0);tracker.Clear();device[8]="BBB";tracker.Accept(Packet(false,201,0x10,Frame(false,0,77,1)),10,device,owner);Check(tracker.Matches().Count==0,"Old device generation retained");
  Console.WriteLine("PASS: protocol versions, TCP segments/retransmits/reordering/wrap, failed/tag replies, old-flow rejection, PID/port reuse, close and device invalidation");
 }
 static byte[] Read(Stream stream,int length){var result=new byte[length];int offset=0;while(offset<length){int count=stream.Read(result,offset,length-offset);if(count==0)throw new EndOfStreamException();offset+=count;}return result;}
 static TcpClient Connect(uint id) {
  var client=new TcpClient();try {client.Connect(IPAddress.Loopback,27015);client.ReceiveTimeout=3000;client.SendTimeout=3000;
   string xml="<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>MessageType</key><string>Connect</string><key>DeviceID</key><integer>"+id+"</integer><key>PortNumber</key><integer>"+(ushort)IPAddress.HostToNetworkOrder(unchecked((short)62078))+"</integer><key>ProgName</key><string>SafeDetachTest</string></dict></plist>";
   byte[] body=Encoding.UTF8.GetBytes(xml);using(var memory=new MemoryStream())using(var writer=new BinaryWriter(memory)){writer.Write((uint)(16+body.Length));writer.Write(1u);writer.Write(8u);writer.Write(1u);writer.Write(body);byte[] frame=memory.ToArray();client.GetStream().Write(frame,0,frame.Length);}
   byte[] header=Read(client.GetStream(),16);uint length=BitConverter.ToUInt32(header,0);Check(length>=16&&length<65536,"Invalid response");byte[] frameBytes=new byte[length];Buffer.BlockCopy(header,0,frameBytes,0,16);Buffer.BlockCopy(Read(client.GetStream(),(int)length-16),0,frameBytes,16,(int)length-16);var response=MuxFrame.Parse(frameBytes);Check(response!=null&&response.Result&&response.Value==0,"Device rejected connection");return client;
  }catch{client.Close();throw;}
 }
 static int Fixture(string[] args) {
  using(var first=Connect(uint.Parse(args[1])))using(var second=Connect(uint.Parse(args[2]))) {Console.WriteLine("READY");Console.Out.Flush();Check(Console.ReadLine()=="close-first","Fixture command");first.Close();Console.WriteLine("CLOSED_FIRST");Console.Out.Flush();Check(Console.ReadLine()=="close-all","Fixture command");second.Close();Console.WriteLine("CLOSED_ALL");Console.Out.Flush();Console.ReadLine();}return 0;
 }
 static void Wait(Func<bool> condition,string message){var clock=Stopwatch.StartNew();while(clock.ElapsedMilliseconds<10000){if(condition())return;Thread.Sleep(50);}throw new Exception(message);}
 static string Line(Process process){var line=process.StandardOutput.ReadLineAsync();if(!line.Wait(10000))throw new Exception("Fixture timeout");if(line.Result==null)throw new Exception("Fixture failed: "+process.StandardError.ReadToEnd());return line.Result;}
 static bool Has(AppleConnectionMonitor monitor,int pid,uint device){foreach(var match in monitor.Snapshot())if(match.Client.Pid==pid&&match.DeviceId==device)return true;return false;}
 static bool ScanHas(AppleConnectionMonitor monitor,string instance,int pid){foreach(string line in monitor.Scan(instance)){var fields=line.Split('\t');if(fields[0]=="ERROR")throw new Exception(HandleScanner.Decode(fields[1]));if(fields[0]=="H"&&fields[1]==pid.ToString())return true;}return false;}
 static void RetryUi() {
  System.Windows.Forms.Application.EnableVisualStyles();System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
  using(var form=new MainWindow(false)) {
   form.ShowInTaskbar=false;form.StartPosition=System.Windows.Forms.FormStartPosition.Manual;form.Location=new System.Drawing.Point(-30000,-30000);form.Show();
   var flags=BindingFlags.NonPublic|BindingFlags.Instance;var field=typeof(MainWindow).GetField("appleMonitor",flags);var previous=(AppleConnectionMonitor)field.GetValue(form);
   // Simulate the completed failure before installation without altering the installed driver.
   typeof(AppleConnectionMonitor).GetField("captureUnavailable",flags).SetValue(previous,true);
   typeof(MainWindow).GetMethod("UpdateNpcapNotice",flags).Invoke(form,null);
   typeof(MainWindow).GetMethod("RetryNpcap",flags).Invoke(form,null);
   var busy=typeof(MainWindow).GetField("busy",flags);var clock=Stopwatch.StartNew();
   while((bool)busy.GetValue(form)&&clock.ElapsedMilliseconds<10000){System.Windows.Forms.Application.DoEvents();Thread.Sleep(10);}
   Check(!(bool)busy.GetValue(form),"Install retry did not finish");var replacement=(AppleConnectionMonitor)field.GetValue(form);
   Check(!object.ReferenceEquals(previous,replacement)&&replacement.Status==null&&!replacement.CaptureUnavailable,"Install retry did not reinitialize live capture");
   var notice=(System.Windows.Forms.Panel)typeof(MainWindow).GetField("npcapNotice",flags).GetValue(form);Check(!notice.Visible,"Retry did not dismiss dependency notice");
   form.Close();
  }
  Console.WriteLine("PASS: in-app retry replaces failed monitor, initializes real Npcap, collapses notice and closes cleanly");
 }
 static void Hardware() {
  var identities=AppleServiceScanner.DeviceIdentities();Check(identities.Count==2,"Hardware test requires two USB Apple devices");var ids=new List<uint>(identities.Keys);var instances=new Dictionary<uint,string>();
  foreach(var item in Devices.Enumerate())if(item.IsPortable){string physical=PortableTargets.PhysicalInstance(item.InstanceId);string serial=AppleServiceScanner.Normalize(physical.Substring(physical.LastIndexOf('\\')+1));foreach(uint id in ids)if(identities[id]==serial)instances[id]=item.InstanceId;}
  Check(instances.Count==2,"PnP identities do not match both devices");
  using(var monitor=new AppleConnectionMonitor()) {monitor.Start();try{Wait(delegate{return monitor.Status==null;},"Monitor not ready");}catch{throw new Exception("Monitor not ready: "+monitor.Status);}
   var info=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--fixture "+ids[0]+" "+ids[1]){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
   using(var child=Process.Start(info))try {
    Check(Line(child)=="READY","Fixture not ready");Wait(delegate{return Has(monitor,child.Id,ids[0])&&Has(monitor,child.Id,ids[1]);},"Both devices not recognized: "+monitor.Status);
    Check(ScanHas(monitor,instances[ids[0]],child.Id)&&ScanHas(monitor,instances[ids[1]],child.Id),"UI scan did not map both PnP devices");Console.WriteLine("PASS: real two-device handshakes, successful responses, child PID and exact PnP mapping");
    child.StandardInput.WriteLine("close-first");Check(Line(child)=="CLOSED_FIRST","Close first failed");Wait(delegate{return !Has(monitor,child.Id,ids[0])&&Has(monitor,child.Id,ids[1]);},"Close did not remove only the first device");Check(!ScanHas(monitor,instances[ids[0]],child.Id)&&ScanHas(monitor,instances[ids[1]],child.Id),"Closed device still in UI scan");
    monitor.InvalidateDevices();Wait(delegate{return !Has(monitor,child.Id,ids[1]);},"Hotplug invalidation retained connection");Thread.Sleep(1200);Check(!Has(monitor,child.Id,ids[1]),"Existing connection was reassigned after invalidation");
    child.StandardInput.WriteLine("close-all");Check(Line(child)=="CLOSED_ALL","Close all failed");child.StandardInput.WriteLine("exit");Check(child.WaitForExit(5000)&&child.ExitCode==0,"Fixture exit failed");Console.WriteLine("PASS: close one device, preserve the other, invalidate old generation, no reassignment, clean fixture shutdown");
   } finally {if(!child.HasExited){child.Kill();child.WaitForExit();}}
  }
  RetryUi();
 }
 [STAThread] static int Main(string[] args){try{if(args.Length>0&&args[0]=="--fixture")return Fixture(args);Unit();if(args.Length==1&&args[0]=="--hardware")Hardware();else if(args.Length==1&&args[0]=="--retry-ui")RetryUi();return 0;}catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex.GetType().Name+": "+ex.Message);return 1;}}
}

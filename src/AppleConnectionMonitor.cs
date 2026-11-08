using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SafeDetach {
 public sealed class AppleConnectionMonitor:IDisposable {
  // Load from the system Npcap directory only; Npcap itself is an optional installed dependency.
  sealed class Capture:IDisposable {
   [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);
   [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
   [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr Open([MarshalAs(UnmanagedType.LPStr)]string device,int snap,int promisc,int timeout,IntPtr error);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Compile(IntPtr handle,IntPtr program,[MarshalAs(UnmanagedType.LPStr)]string filter,int optimize,uint mask);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int SetFilter(IntPtr handle,IntPtr program);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void FreeCode(IntPtr program);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Nonblock(IntPtr handle,int enabled,IntPtr error);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DataLink(IntPtr handle);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Next(IntPtr handle,out IntPtr header,out IntPtr data);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Stats(IntPtr handle,IntPtr stats);
   [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void Close(IntPtr handle);
   IntPtr module,handle;Next next;Close close;Stats stats;public int Link;
   T Function<T>(string name)where T:class {IntPtr address=GetProcAddress(module,name);if(address==IntPtr.Zero)throw new InvalidOperationException("Npcap 接口不可用。");return Marshal.GetDelegateForFunctionPointer(address,typeof(T)) as T;}
   public Capture() {
    string path=NpcapSupport.LibraryPath;if(!NpcapSupport.IsInstalled)throw new InvalidOperationException("Apple 连接识别需要安装 Npcap。");
    module=LoadLibraryEx(path,IntPtr.Zero,0x1100);if(module==IntPtr.Zero)throw new InvalidOperationException("无法加载 Npcap，请检查安装。");
    IntPtr error=Marshal.AllocHGlobal(256),program=Marshal.AllocHGlobal(16);bool compiled=false;
    try {close=Function<Close>("pcap_close");next=Function<Next>("pcap_next_ex");stats=Function<Stats>("pcap_stats");handle=Function<Open>("pcap_open_live")("\\Device\\NPF_Loopback",65536,0,100,error);if(handle==IntPtr.Zero)throw new InvalidOperationException("Apple 连接监听不可用，请尝试管理员模式。");
     if(Function<Compile>("pcap_compile")(handle,program,"ip and tcp and src host 127.0.0.1 and dst host 127.0.0.1 and port 27015",1,0xffffffff)!=0)throw new InvalidOperationException("无法设置 Apple 连接筛选器。");compiled=true;
     if(Function<SetFilter>("pcap_setfilter")(handle,program)!=0||Function<Nonblock>("pcap_setnonblock")(handle,1,error)!=0)throw new InvalidOperationException("无法启动 Apple 连接监听。");
     Link=Function<DataLink>("pcap_datalink")(handle);if(Link!=0&&Link!=1&&Link!=101&&Link!=108&&Link!=113)throw new InvalidOperationException("Npcap 回环格式不受支持。");
    }catch{if(compiled){Function<FreeCode>("pcap_freecode")(program);compiled=false;}Dispose();throw;}finally{if(compiled)Function<FreeCode>("pcap_freecode")(program);Marshal.FreeHGlobal(program);Marshal.FreeHGlobal(error);}
   }
   public int Read(out IntPtr header,out IntPtr data){return next(handle,out header,out data);}
   public uint Dropped(){IntPtr data=Marshal.AllocHGlobal(64);try{if(stats(handle,data)!=0)throw new InvalidOperationException("无法检查 Apple 监听状态。");return unchecked((uint)Marshal.ReadInt32(data,4)+(uint)Marshal.ReadInt32(data,8));}finally{Marshal.FreeHGlobal(data);}}
   public void Dispose(){if(handle!=IntPtr.Zero){close(handle);handle=IntPtr.Zero;}if(module!=IntPtr.Zero){FreeLibrary(module);module=IntPtr.Zero;}}
  }
  readonly object sync=new object();readonly MuxSessionTracker tracker=new MuxSessionTracker();
  Thread thread;volatile bool stopped;volatile bool invalidate;volatile bool initialized;bool running,captureUnavailable;AppleClientIdentity observedService;string error="Apple 连接监听正在启动。";Dictionary<uint,string> devices=new Dictionary<uint,string>();List<AppleConnectionMatch> current=new List<AppleConnectionMatch>();
  public void Start(){lock(sync){if(thread!=null||stopped)return;thread=new Thread(Work) {IsBackground=true,Name="Apple connection monitor"};thread.Start();}}
  public void WaitForInitialization(int timeout){var clock=Stopwatch.StartNew();while(!initialized&&!stopped&&clock.ElapsedMilliseconds<timeout)Thread.Sleep(50);}
  public bool CaptureUnavailable {get{lock(sync)return captureUnavailable;}}
  public void InvalidateDevices(){invalidate=true;lock(sync){current.Clear();}}
  static long Clock(){return (long)(Stopwatch.GetTimestamp()*1000.0/Stopwatch.Frequency);}
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exited,out long kernel,out long user);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder path,ref int length);
  static AppleClientIdentity ProcessIdentity(int pid){IntPtr handle=OpenProcess(0x1000,false,pid);if(handle==IntPtr.Zero)return null;try{long created,exited,kernel,user;if(!GetProcessTimes(handle,out created,out exited,out kernel,out user)||exited!=0)return null;var path=new StringBuilder(1024);int length=path.Capacity;string name=QueryFullProcessImageName(handle,0,path,ref length)?Path.GetFileNameWithoutExtension(path.ToString()):"进程 "+pid;return new AppleClientIdentity {Pid=pid,Started=DateTime.FromFileTimeUtc(created).Ticks,Name=name};}finally{CloseHandle(handle);}}
  static AppleClientIdentity Service(){using(var query=new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Service WHERE Name='Apple Mobile Device Service'"))using(var services=query.Get())foreach(ManagementObject service in services)using(service){int pid=Convert.ToInt32(service["ProcessId"]);if(pid<=0)continue;using(var processQuery=new ManagementObjectSearcher("SELECT CreationDate FROM Win32_Process WHERE ProcessId="+pid))using(var processes=processQuery.Get())foreach(ManagementObject process in processes)using(process){string created=Convert.ToString(process["CreationDate"]);if(created.Length>0)return new AppleClientIdentity {Pid=pid,Started=ManagementDateTimeConverter.ToDateTime(created).ToUniversalTime().Ticks,Name="Apple Mobile Device Service"};}throw new InvalidOperationException("无法读取 Apple 服务身份，请使用管理员模式。");}return null;}
  public static AppleClientIdentity Owner(List<AppleServiceScanner.Connection> rows,int port,int servicePid,int self) {
   int client=0;bool listener=false,paired=false;foreach(var row in rows){if(row.Pid==servicePid&&row.State==2&&row.LocalAddress==0x0100007f&&row.LocalPort==27015)listener=true;
    if(row.State!=5||row.LocalAddress!=0x0100007f||row.RemoteAddress!=0x0100007f)continue;if(row.Pid==servicePid&&row.LocalPort==27015&&row.RemotePort==port)paired=true;
    if(row.LocalPort==port&&row.RemotePort==27015){if(client!=0&&client!=row.Pid)return null;client=row.Pid;}}
   return listener&&paired&&client>4&&client!=servicePid&&client!=self?ProcessIdentity(client):null;
  }
  static bool SameDevices(Dictionary<uint,string> a,Dictionary<uint,string> b){if(a.Count!=b.Count)return false;foreach(var item in a){string serial;if(!b.TryGetValue(item.Key,out serial)||item.Value!=serial)return false;}return true;}
  void Work() {
   try {using(var capture=new Capture()) {
    AppleClientIdentity service=null;long refresh=0,serviceRefresh=0;uint dropped=capture.Dropped();int self=Process.GetCurrentProcess().Id;
    while(!stopped) {
     long now=Clock();
     if(invalidate){invalidate=false;tracker.Clear();devices.Clear();refresh=0;}
     if(now>=refresh){refresh=now+500;
      try {
       if(now>=serviceRefresh){serviceRefresh=now+2000;var next=Service();if(service==null||!service.Same(next)){tracker.Clear();devices.Clear();}service=next;}
       if(service==null){tracker.Clear();devices.Clear();lock(sync){current.Clear();error="Apple 设备服务未运行。";running=false;}}
       else {var map=AppleServiceScanner.DeviceIdentities();if(!SameDevices(devices,map)){tracker.Clear();devices=map;}
        var rows=AppleServiceScanner.Connections();tracker.Prune(now,delegate(int port){return Owner(rows,port,service.Pid,self);});
        uint lost=capture.Dropped();if(lost!=dropped){tracker.Clear();dropped=lost;}
        lock(sync){current=tracker.Matches();observedService=service;running=true;error=null;}
       }
      }catch(Exception){tracker.Clear();devices.Clear();lock(sync){current.Clear();running=false;error="Apple 连接监听暂不可用，请重试。";}}
      initialized=true;
     }
     int count=0;while(!stopped&&count++<256){IntPtr header,data;int result=capture.Read(out header,out data);if(result==0)break;if(result<0)throw new InvalidOperationException("Apple 连接监听已中断，请重新启动程序。");
      int length=Marshal.ReadInt32(header,8);if(length<0||length>65536)continue;var bytes=new byte[Math.Min(length,128)];Marshal.Copy(data,bytes,0,bytes.Length);var packet=MuxPacket.Parse(bytes,length,capture.Link);if(packet==null)continue;
      if(tracker.NeedsPayload(packet)&&packet.PayloadLength>0){packet.Payload=new byte[packet.PayloadLength];Marshal.Copy(IntPtr.Add(data,packet.PayloadOffset),packet.Payload,0,packet.Payload.Length);}
      if(service!=null)tracker.Accept(packet,Clock(),devices,delegate(int port){return Owner(AppleServiceScanner.Connections(),port,service.Pid,self);});
     }
     Thread.Sleep(5);
    }
   }}catch(Exception ex){lock(sync){current.Clear();running=false;captureUnavailable=true;error=ex is InvalidOperationException?ex.Message:"Apple 连接监听不可用，请检查 Npcap。";}initialized=true;}
  }
  public List<AppleConnectionMatch> Snapshot(){lock(sync){return new List<AppleConnectionMatch>(current);}}
  public string Status {get{lock(sync)return running?null:error;}}
  public string[] Scan(string instance) {
   try {
    string physical=PortableTargets.PhysicalInstance(instance);if(!physical.StartsWith("USB\\VID_05AC&",StringComparison.OrdinalIgnoreCase))return new[]{"DONE\t0\t0"};string serial=AppleServiceScanner.Normalize(physical.Substring(physical.LastIndexOf('\\')+1));
    for(int wait=0;wait<80&&!initialized&&!stopped;wait++)Thread.Sleep(50);var lines=new List<string>();var seen=new HashSet<string>();List<AppleConnectionMatch> snapshot;string failure;AppleClientIdentity knownService;lock(sync){failure=running?null:error;snapshot=new List<AppleConnectionMatch>(current);knownService=observedService;}if(failure!=null)return new[]{"ERROR\t"+HandleScanner.Encode(failure)};
    var rows=AppleServiceScanner.Connections();var registered=Service();if(knownService==null||!knownService.Same(registered)){InvalidateDevices();return new[]{"ERROR\t"+HandleScanner.Encode("Apple 设备服务已变更，请重新扫描。")};}foreach(var match in snapshot)if(match.Serial==serial&&match.Client.Same(Owner(rows,match.Port,registered.Pid,Process.GetCurrentProcess().Id))){string key=match.Client.Pid+":"+match.Client.Started;if(seen.Add(key))lines.Add("H\t"+match.Client.Pid+"\t"+match.Client.Started+"\t"+HandleScanner.Encode(match.Client.Name)+"\t"+HandleScanner.Encode("Apple 设备连接"));}
    if(lines.Count==0)lines.Add("NOTE\t"+HandleScanner.Encode("旧 Apple 连接需重新连接应用后识别。"));lines.Add("DONE\t"+seen.Count+"\t0");return lines.ToArray();
   }catch(Exception ex){return new[]{"ERROR\t"+HandleScanner.Encode(ex.Message)};}
  }
  public void Dispose(){stopped=true;if(thread!=null&&thread.IsAlive)thread.Join(2000);/* Background owns its native resources until any in-flight query returns. */}
 }
}

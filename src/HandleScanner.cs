using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

namespace SafeDetach {
 // Runs only in a disposable helper process. A stalled filesystem driver must
 // never block the UI. Results are streamed so partial scans remain useful.
 public static class HandleScanner {
  public sealed class ProbeCache:IDisposable {
   sealed class Entry {public IntPtr Handle;public string Path;}
   readonly Dictionary<string,Entry> entries=new Dictionary<string,Entry>();readonly Queue<string> order=new Queue<string>();bool supported=true;Entry previous;int previousPid;uint previousAccess;
   [DllImport("kernelbase.dll")] static extern bool CompareObjectHandles(IntPtr first,IntPtr second);
   string Key(long address,uint access){return address+":"+access;}
   public bool TryGet(long address,uint access,IntPtr handle,out string path,int pid=0){path=null;Entry entry;if(!supported)return false;if(address==0){if(previous==null||previousPid!=pid||previousAccess!=access)return false;entry=previous;}else if(!entries.TryGetValue(Key(address,access),out entry))return false;try{if(!CompareObjectHandles(entry.Handle,handle))return false;path=entry.Path;return true;}catch(EntryPointNotFoundException){supported=false;Dispose();return false;}}
   public void Remember(long address,uint access,IntPtr handle,string path){if(!supported||address==0||string.IsNullOrEmpty(path))return;string key=Key(address,access);if(entries.ContainsKey(key))return;IntPtr pin;if(!DuplicateHandle(GetCurrentProcess(),handle,GetCurrentProcess(),out pin,0,false,DuplicateSameAccess))return;
    if(entries.Count>=256){string oldest=order.Dequeue();CloseHandle(entries[oldest].Handle);entries.Remove(oldest);}entries.Add(key,new Entry {Handle=pin,Path=path});order.Enqueue(key);}
   // Recent Windows versions redact object addresses. Keep just the last successful
   // probe per current process in that case, reusing the already duplicated handle.
   public bool RememberOwned(int pid,long address,uint access,IntPtr handle,string path){if(!supported||string.IsNullOrEmpty(path))return false;if(address!=0){Remember(address,access,handle,path);return false;}if(previous!=null)CloseHandle(previous.Handle);previous=new Entry {Handle=handle,Path=path};previousPid=pid;previousAccess=access;return true;}
   public void Dispose(){foreach(var entry in entries.Values)CloseHandle(entry.Handle);entries.Clear();order.Clear();if(previous!=null){CloseHandle(previous.Handle);previous=null;}}
  }
  public static Func<IntPtr,string> DiagnosticUnnamedFile;
  public static PortableIdentity SelectedPortableIdentity;
  const uint DuplicateSameAccess=2;
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int kind,IntPtr data,int length,out int needed);
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr copy,uint access,bool inherit,uint options);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern uint GetFileType(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr handle,StringBuilder name,uint length,uint flags);
  [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr handle,int kind,IntPtr buffer,int length,out int needed);
  public static string ObjectName(IntPtr handle) {
   IntPtr memory=Marshal.AllocHGlobal(65536);
   try{return ObjectName(handle,memory);}finally{Marshal.FreeHGlobal(memory);}
  }
  static string ObjectName(IntPtr handle,IntPtr memory){int needed;if(NtQueryObject(handle,1,memory,65536,out needed)!=0)return "";int bytes=(ushort)Marshal.ReadInt16(memory);return bytes==0?"":Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,IntPtr.Size),bytes/2);}
  public static int QuerySingle(int pid,long value) {
   IntPtr source=OpenProcess(0x40,false,pid);if(source==IntPtr.Zero)return 1;
   try{IntPtr copy;if(!DuplicateHandle(source,new IntPtr(value),GetCurrentProcess(),out copy,0,false,2))return 1;try{Console.WriteLine(Encode(ObjectName(copy)));return 0;}finally{CloseHandle(copy);}}finally{CloseHandle(source);}
  }
  static string PipeName(int pid,long value) {
   using(var child=Process.Start(new ProcessStartInfo(typeof(HandleScanner).Assembly.Location,"--handle-name "+pid+" "+value){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})) {
    var read=child.StandardOutput.ReadToEndAsync();if(!child.WaitForExit(750)){child.Kill();child.WaitForExit();return "";}return child.ExitCode==0?Decode(read.Result.Trim()):"";
   }
  }
  public static int Run(string[] roots) {return Run(roots,false);}
  public static int Run(string[] roots,bool native) {return Run(roots,native,0);}
  public static int Run(string[] roots,bool native,int onlyPid) {
   int size=1024*1024, needed; IntPtr buffer=IntPtr.Zero;
   using(var marker=File.OpenRead(typeof(HandleScanner).Assembly.Location)) {
   try {
    for(;;) {
     buffer=Marshal.AllocHGlobal(size);
     int status=NtQuerySystemInformation(64,buffer,size,out needed);
     if(status==0) break;
     Marshal.FreeHGlobal(buffer); buffer=IntPtr.Zero;
     if(status!=unchecked((int)0xc0000004)) throw new InvalidOperationException("读取句柄表失败："+status);
     size=Math.Max(size*2,needed+65536);
     if(size>256*1024*1024) throw new InvalidOperationException("句柄表超出扫描限制。");
    }
    long count=Marshal.ReadIntPtr(buffer).ToInt64(); int width=IntPtr.Size==8?40:28;
    int fileType=-1,selfId=Process.GetCurrentProcess().Id;
    for(long i=0;i<count;i++) {IntPtr entry=new IntPtr(buffer.ToInt64()+IntPtr.Size*2+i*width);if(Marshal.ReadIntPtr(entry,IntPtr.Size).ToInt64()==selfId&&Marshal.ReadIntPtr(entry,IntPtr.Size*2)==marker.SafeFileHandle.DangerousGetHandle()){fileType=(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6);break;}}
    if(fileType<0)throw new InvalidOperationException("无法确定文件句柄类型。");
    // Pin/cache only objects actually repeated in this snapshot. Unique handles
    // should not pay for an extra DuplicateHandle/CloseHandle pair.
    var seenObjects=new HashSet<long>();var repeatedObjects=new HashSet<long>();for(long i=0;i<count;i++){IntPtr entry=new IntPtr(buffer.ToInt64()+IntPtr.Size*2+i*width);if((ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)!=fileType)continue;long address=Marshal.ReadIntPtr(entry).ToInt64();if(address!=0&&!seenObjects.Add(address))repeatedObjects.Add(address);}
    var sources=new Dictionary<int,IntPtr>(); var emitted=new HashSet<string>();
    int denied=0, inspected=0, self=Process.GetCurrentProcess().Id,cacheHits=0,pathQueries=0,deviceQueries=0;var processStarts=new Dictionary<int,long>();var processNames=new Dictionary<int,string>();var name=new StringBuilder(32768);IntPtr nameMemory=Marshal.AllocHGlobal(65536);var cache=new ProbeCache();
    try {
     for(long i=0;i<count;i++) {
      IntPtr entry=new IntPtr(buffer.ToInt64()+IntPtr.Size*2+i*width);
      if(onlyPid==0&&(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)!=fileType)continue;
      long rawPid=Marshal.ReadIntPtr(entry,IntPtr.Size).ToInt64();
      if(rawPid<=4 || rawPid>int.MaxValue || rawPid==self) continue;
      int pid=(int)rawPid; IntPtr source;
      if(onlyPid!=0&&pid!=onlyPid)continue;
      if(!sources.TryGetValue(pid,out source)) { source=OpenProcess(0x1040,false,pid); sources.Add(pid,source); if(source==IntPtr.Zero) denied++; }
      if(source==IntPtr.Zero) continue;
      IntPtr copy;
      if(!DuplicateHandle(source,Marshal.ReadIntPtr(entry,IntPtr.Size*2),GetCurrentProcess(),out copy,0,false,DuplicateSameAccess)) continue;
      try {
       uint kind=GetFileType(copy);if(!native&&kind!=1)continue;if(native&&kind==3&&onlyPid==0)continue;
       inspected++;
       string path="";long address=Marshal.ReadIntPtr(entry).ToInt64();uint access=unchecked((uint)Marshal.ReadInt32(entry,IntPtr.Size*3));
       bool cached=onlyPid==0&&(address==0||repeatedObjects.Contains(address))&&cache.TryGet(address,access,copy,out path,pid);
       if(cached){cacheHits++;}
       else if(native) {
        // A WPD identity request can only succeed for FILE_DEVICE_UNKNOWN.
        // Reject ordinary filesystem handles before querying their object names.
        bool portable=SelectedPortableIdentity!=null&&onlyPid==0;
        if(portable&&PortableProtocol.DeviceType(copy)!=0x22)continue;
        pathQueries++;path=kind==3?PipeName(pid,Marshal.ReadIntPtr(entry,IntPtr.Size*2).ToInt64()):ObjectName(copy,nameMemory);
        if(SelectedPortableIdentity!=null&&path.Length==0&&kind!=3&&(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)==fileType&&(portable||PortableProtocol.DeviceType(copy)==0x22)) {
         deviceQueries++;try{path="WPD:"+PortableProtocol.Read(copy).Key;}catch(System.ComponentModel.Win32Exception){}catch(InvalidDataException){}catch(COMException){}catch(TimeoutException){}
        }
        if(onlyPid!=0&&path.Length==0&&kind!=3&&(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)==fileType){Console.WriteLine("DEBUG\t"+Marshal.ReadIntPtr(entry,IntPtr.Size*2)+"\t"+"UNNAMED File");if(DiagnosticUnnamedFile!=null)Console.WriteLine(DiagnosticUnnamedFile(copy));}
       } else {
       name.Length=0;pathQueries++;uint n=GetFinalPathNameByHandle(copy,name,(uint)name.Capacity,0);
       if(n==0 || n>=name.Capacity) continue;
       path=name.ToString(); if(path.StartsWith("\\\\?\\")) path=path.Substring(4);
       }
       if(!cached&&onlyPid==0&&(address==0||repeatedObjects.Contains(address))&&cache.RememberOwned(pid,address,access,copy,path))copy=IntPtr.Zero;
       bool matches=false; foreach(string root in roots) if((native&&path.Equals(root,StringComparison.OrdinalIgnoreCase))||path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase)) { matches=true; break; }
       if(!matches || !emitted.Add(pid+"|"+path)) continue;
       long started;string processName;if(!processStarts.TryGetValue(pid,out started)){started=0;processName="未知进程";long created,exit,kernel,user;if(GetProcessTimes(source,out created,out exit,out kernel,out user))started=DateTime.FromFileTimeUtc(created).Ticks;try{using(var p=Process.GetProcessById(pid))if(p.StartTime.ToUniversalTime().Ticks==started)processName=p.ProcessName;}catch{}processStarts[pid]=started;processNames[pid]=processName;}else processName=processNames[pid];
       Console.WriteLine("H\t"+pid+"\t"+started+"\t"+Encode(processName)+"\t"+Encode(SelectedPortableIdentity!=null?"设备连接":path)); Console.Out.Flush();
      } finally { if(copy!=IntPtr.Zero)CloseHandle(copy); }
     }
    } finally {cache.Dispose();Marshal.FreeHGlobal(nameMemory);foreach(IntPtr handle in sources.Values) if(handle!=IntPtr.Zero) CloseHandle(handle); }
    if(Environment.GetEnvironmentVariable("SAFEDETACH_STATS")=="1")Console.WriteLine("STATS\tH\t"+inspected+"\t"+cacheHits+"\t"+pathQueries+"\t"+deviceQueries+"\t"+repeatedObjects.Count);
    Console.WriteLine("DONE\t"+inspected+"\t"+denied); return 0;
   } catch(Exception ex) { Console.WriteLine("ERROR\t"+Encode(ex.Message)); return 1; }
   finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
   }
  }
  public static string Encode(string value) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(value)); }
  public static string Decode(string value) { return Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
 }
}





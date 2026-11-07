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
   try{int needed;if(NtQueryObject(handle,1,memory,65536,out needed)!=0)return "";int bytes=(ushort)Marshal.ReadInt16(memory);return bytes==0?"":Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,IntPtr.Size),bytes/2);}finally{Marshal.FreeHGlobal(memory);}
  }
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
    var sources=new Dictionary<int,IntPtr>(); var emitted=new HashSet<string>();
    int denied=0, inspected=0, self=Process.GetCurrentProcess().Id;
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
       string path;
       if(native) {
        path=kind==3?PipeName(pid,Marshal.ReadIntPtr(entry,IntPtr.Size*2).ToInt64()):ObjectName(copy);
        if(SelectedPortableIdentity!=null&&path.Length==0&&kind!=3&&(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)==fileType&&PortableProtocol.DeviceType(copy)==0x22) {
         try{if(PortableProtocol.Read(copy).Key==SelectedPortableIdentity.Key)path="WPD:"+SelectedPortableIdentity.Key;}catch(System.ComponentModel.Win32Exception){}catch(InvalidDataException){}catch(COMException){}catch(TimeoutException){}
        }
        if(onlyPid!=0&&path.Length==0&&kind!=3&&(ushort)Marshal.ReadInt16(entry,IntPtr.Size*3+6)==fileType){Console.WriteLine("DEBUG\t"+Marshal.ReadIntPtr(entry,IntPtr.Size*2)+"\t"+"UNNAMED File");if(DiagnosticUnnamedFile!=null)Console.WriteLine(DiagnosticUnnamedFile(copy));}
       } else {
       var name=new StringBuilder(32768); uint n=GetFinalPathNameByHandle(copy,name,(uint)name.Capacity,0);
       if(n==0 || n>=name.Capacity) continue;
       path=name.ToString(); if(path.StartsWith("\\\\?\\")) path=path.Substring(4);
       }
       bool matches=false; foreach(string root in roots) if((native&&path.Equals(root,StringComparison.OrdinalIgnoreCase))||path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase)) { matches=true; break; }
       if(!matches || !emitted.Add(pid+"|"+path)) continue;
       long started=0; string processName="未知进程";
       long created,exit,kernel,user;
       if(GetProcessTimes(source,out created,out exit,out kernel,out user)) started=DateTime.FromFileTimeUtc(created).Ticks;
       try { using(var p=Process.GetProcessById(pid)) { if(p.StartTime.ToUniversalTime().Ticks==started) processName=p.ProcessName; } } catch { }
       Console.WriteLine("H\t"+pid+"\t"+started+"\t"+Encode(processName)+"\t"+Encode(SelectedPortableIdentity!=null?"设备连接":path)); Console.Out.Flush();
      } finally { CloseHandle(copy); }
     }
    } finally { foreach(IntPtr handle in sources.Values) if(handle!=IntPtr.Zero) CloseHandle(handle); }
    Console.WriteLine("DONE\t"+inspected+"\t"+denied); return 0;
   } catch(Exception ex) { Console.WriteLine("ERROR\t"+Encode(ex.Message)); return 1; }
   finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
   }
  }
  public static string Encode(string value) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(value)); }
  public static string Decode(string value) { return Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
 }
}





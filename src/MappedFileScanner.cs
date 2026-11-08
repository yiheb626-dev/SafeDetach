using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SafeDetach {
 public static class MappedFileScanner {
  [StructLayout(LayoutKind.Sequential)] struct MemoryInfo {
   public IntPtr BaseAddress,AllocationBase;
   public uint AllocationProtect;
   public UIntPtr RegionSize;
   public uint State,Protect,Type;
  }
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr process,IntPtr address,out MemoryInfo info,UIntPtr length);
  [DllImport("psapi.dll",CharSet=CharSet.Unicode)] static extern uint GetMappedFileNameW(IntPtr process,IntPtr address,StringBuilder name,int length);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint QueryDosDevice(string device,StringBuilder target,int length);
  public static int Run(string[] roots) {
   var mappings=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
   foreach(string root in roots){var target=new StringBuilder(1024);if(QueryDosDevice(root.TrimEnd('\\'),target,target.Capacity)!=0)mappings[target.ToString()]=root.TrimEnd('\\');}
   int denied=0,fileQueries=0,allocationHits=0;
   foreach(var process in Process.GetProcesses()) using(process) {
    IntPtr handle=OpenProcess(0x410,false,process.Id);if(handle==IntPtr.Zero){denied++;continue;}
    try {
     long created,exit,kernel,user;if(!GetProcessTimes(handle,out created,out exit,out kernel,out user))continue;
     long started=DateTime.FromFileTimeUtc(created).Ticks;string name;try{if(process.StartTime.ToUniversalTime().Ticks!=started)continue;name=process.ProcessName;}catch{continue;}
     ulong address=0;var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var allocations=new HashSet<IntPtr>();var file=new StringBuilder(32768);int size=Marshal.SizeOf(typeof(MemoryInfo));
     for(int region=0;region<1000000;region++) {
      MemoryInfo info;if(VirtualQueryEx(handle,new IntPtr((long)address),out info,(UIntPtr)size)==UIntPtr.Zero)break;
      ulong next=(ulong)info.BaseAddress.ToInt64()+info.RegionSize.ToUInt64();if(next<=address||next>long.MaxValue)break;
      if(info.State==0x1000&&(info.Type==0x40000||info.Type==0x1000000)) {
       if(allocations.Contains(info.AllocationBase)){allocationHits++;address=next;continue;}
       file.Length=0;fileQueries++;
       if(GetMappedFileNameW(handle,info.BaseAddress,file,file.Capacity)>0){allocations.Add(info.AllocationBase);foreach(var map in mappings) {
        string path=file.ToString();if(!path.StartsWith(map.Key+"\\",StringComparison.OrdinalIgnoreCase))continue;
        path=map.Value+path.Substring(map.Key.Length);
        if(seen.Add(path)){Console.WriteLine("M\t"+process.Id+"\t"+started+"\t"+HandleScanner.Encode(name)+"\t"+HandleScanner.Encode(path));Console.Out.Flush();}
       }}
      }
      address=next;
     }
    }finally{CloseHandle(handle);}
   }
   if(Environment.GetEnvironmentVariable("SAFEDETACH_STATS")=="1")Console.WriteLine("STATS\tM\t"+fileQueries+"\t"+allocationHits);
   Console.WriteLine("DONE\t0\t"+denied);return 0;
  }
 }
}

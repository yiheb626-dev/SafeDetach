using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SafeDetach {
 public static class ProcessActions {
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessCritical(IntPtr process,out bool critical);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint exitCode);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  public static void Terminate(int pid,long expectedStart) {
   if(pid<=4 || pid==Process.GetCurrentProcess().Id || expectedStart==0) throw new InvalidOperationException("无法安全确认进程身份，禁止结束。");
   IntPtr handle=OpenProcess(0x101001,false,pid);
   if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    long created,exit,kernel,user;
    if(!GetProcessTimes(handle,out created,out exit,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if(DateTime.FromFileTimeUtc(created).Ticks!=expectedStart) throw new InvalidOperationException("原进程已退出，PID 已被复用，请重新扫描。");
    bool critical;
    if(!IsProcessCritical(handle,out critical)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if(critical) throw new InvalidOperationException("这是 Windows 关键进程，禁止结束。");
    if(!TerminateProcess(handle,1)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if(WaitForSingleObject(handle,3000)!=0)throw new InvalidOperationException("进程仍在退出，请稍后重新扫描。");
   } finally { CloseHandle(handle); }
  }
 }
}

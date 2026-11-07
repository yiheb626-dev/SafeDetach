using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SafeDetach {
 public static class WindowClueScanner {
  delegate bool WindowCallback(IntPtr window,IntPtr state);
  [DllImport("user32.dll")] static extern bool EnumWindows(WindowCallback callback,IntPtr state);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window,StringBuilder text,int length);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
  class Viewer {public int Pid;public long Started;public string Name,File;}
  public static bool IsFileTitle(string title) {
   if(string.IsNullOrWhiteSpace(title)||title.IndexOfAny(Path.GetInvalidFileNameChars())>=0)return false;
   string ext=Path.GetExtension(title).ToLowerInvariant();
   return Array.IndexOf(".jpg|.jpeg|.png|.heic|.heif|.gif|.bmp|.tif|.tiff|.webp|.raw|.cr2|.nef|.mp4|.mov|.pdf".Split('|'),ext)>=0;
  }
  public static int Run(string[] roots) {
   var viewers=new List<Viewer>();
   EnumWindows(delegate(IntPtr window,IntPtr state) {
    if(!IsWindowVisible(window))return true;var text=new StringBuilder(1024);GetWindowText(window,text,text.Capacity);string title=text.ToString();
    if(!IsFileTitle(title))return true;uint pid;GetWindowThreadProcessId(window,out pid);
    try{using(var process=Process.GetProcessById((int)pid))viewers.Add(new Viewer {Pid=(int)pid,Started=process.StartTime.ToUniversalTime().Ticks,Name=process.ProcessName,File=title});}catch{}
    return true;
   },IntPtr.Zero);
   var queue=new Queue<string>();foreach(string root in roots)queue.Enqueue(root.TrimEnd('\\')+"\\");
   var clock=Stopwatch.StartNew();int visited=0,denied=0;var emitted=new HashSet<string>();
   while(viewers.Count>0&&queue.Count>0&&clock.ElapsedMilliseconds<8000&&visited<10000) {
    string dir=queue.Dequeue();visited++;
    foreach(var viewer in viewers) {
     string path=Path.Combine(dir,viewer.File);
     if(File.Exists(path)&&emitted.Add(viewer.Pid+"|"+path)) {Console.WriteLine("W\t"+viewer.Pid+"\t"+viewer.Started+"\t"+HandleScanner.Encode(viewer.Name)+"\t"+HandleScanner.Encode(path));Console.Out.Flush();}
    }
    try{foreach(string child in Directory.EnumerateDirectories(dir)){if(clock.ElapsedMilliseconds>=8000)break;if((File.GetAttributes(child)&FileAttributes.ReparsePoint)==0)queue.Enqueue(child);}}catch{denied++;}
   }
   Console.WriteLine((viewers.Count>0&&queue.Count>0?"PARTIAL":"DONE")+"\t"+visited+"\t"+denied);return 0;
  }
 }
}


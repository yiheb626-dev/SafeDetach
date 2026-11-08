using System;
using System.Diagnostics;
using System.IO;

namespace SafeDetach {
 public static class NpcapSupport {
  public const string DownloadUrl="https://npcap.com/#download";
  public static string LibraryPath {get{return Path.Combine(Environment.SystemDirectory,"Npcap","wpcap.dll");}}
  public static bool IsInstalled {get{return File.Exists(LibraryPath);}}
  public static void OpenDownloadPage(){Process.Start(new ProcessStartInfo(DownloadUrl){UseShellExecute=true});}
 }
}

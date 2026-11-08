using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using SafeDetach;
class Integration {
 static int Main(string[] args) {
  if(args.Length>0 && args[0]=="hold") {using(var file=File.Open(args[1],FileMode.Open,FileAccess.Read,FileShare.Read)){Console.WriteLine("READY");Console.Out.Flush();Thread.Sleep(60000);}return 0;}
  string root=AppDomain.CurrentDomain.BaseDirectory, filePath=Path.Combine(root,"占用测试.txt");
  Process holder=null;
  try {
   File.WriteAllText(filePath,"SafeDetach integration fixture");
   holder=Process.Start(new ProcessStartInfo(typeof(Integration).Assembly.Location,"hold \""+filePath+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true});
   if(holder.StandardOutput.ReadLine()!="READY")throw new Exception("Fixture not ready");
   long start=holder.StartTime.ToUniversalTime().Ticks;
   string app=Environment.GetEnvironmentVariable("SAFEDETACH_TEST_APP");if(string.IsNullOrEmpty(app))app=Path.Combine(root,"..","release","SafeDetach.exe");
   using(var scanner=Process.Start(new ProcessStartInfo(app,"--scan "+Path.GetPathRoot(filePath).TrimEnd('\\')){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})) {
    var read=scanner.StandardOutput.ReadToEndAsync();
    if(!scanner.WaitForExit(30000)){scanner.Kill();throw new Exception("Scanner timeout");}
    string output=read.Result;bool found=false;
    foreach(string line in output.Split('\n')){string[] p=line.Trim().Split('\t');if(p.Length==5&&p[0]=="H"&&p[1]==holder.Id.ToString()&&HandleScanner.Decode(p[4])==filePath)found=true;}
    if(!found)throw new Exception("Test file holder not detected. Output: "+output);
    if(!output.Contains("DONE\t"))throw new Exception("Incomplete scan");
    Console.WriteLine("PASS: real file handle + PID + Unicode path detection");
   }
   bool rejected=false;try{ProcessActions.Terminate(holder.Id,start+1);}catch(InvalidOperationException){rejected=true;}
   if(!rejected||holder.HasExited)throw new Exception("Identity protection failed");Console.WriteLine("PASS: stale identity rejected");
   bool ejectRequested=false;
   EjectWorkflow.ReleaseAndEject(new ExternalDisk {Name="fixture"},new[]{new Occupant {Pid=holder.Id,Started=start,Name="fixture"}},delegate(Occupant p){ProcessActions.Terminate(p.Pid,p.Started);},delegate(ExternalDisk d){if(!holder.HasExited)throw new Exception("Eject requested before process exit");using(var released=File.Open(filePath,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){}ejectRequested=true;return "fixture-eject";});
   if(!ejectRequested||!holder.WaitForExit(5000))throw new Exception("Termination/eject workflow failed");Console.WriteLine("PASS: force-eject fixture termination and file release before eject request");
   foreach(var disk in Devices.Enumerate()){Console.WriteLine("DEVICE: "+disk+" / "+disk.InstanceId);var refreshed=Devices.RefreshTarget(disk);if(refreshed==null||refreshed.InstanceId!=disk.InstanceId||refreshed.Serial!=disk.Serial)throw new Exception("Targeted identity refresh failed");var wrong=new ExternalDisk {InstanceId=disk.InstanceId,Serial=disk.Serial+"WRONG",IsPortable=disk.IsPortable};if(Devices.RefreshTarget(wrong)!=null)throw new Exception("Targeted refresh accepted changed identity");}
   Console.WriteLine("PASS: device enumeration");return 0;
  }catch(Exception ex){Console.WriteLine("FAIL: "+ex);return 1;}
  finally{if(holder!=null){if(!holder.HasExited)holder.Kill();holder.Dispose();}if(File.Exists(filePath))File.Delete(filePath);}
 }
}

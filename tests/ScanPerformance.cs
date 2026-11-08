using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SafeDetach;
using System.Windows.Forms;

class ScanPerformance {
 [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr copy,uint access,bool inherit,uint options);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static void Check(bool condition,string message){if(!condition)throw new Exception(message);}
 static void FixtureResult(){Console.WriteLine("H\t1234\t100\t"+HandleScanner.Encode("fixture")+"\t"+HandleScanner.Encode("fixture connection"));Console.Out.Flush();}
 static int Fixture(string[] args){
  if(args[1]=="hold") {using(var file=File.Open(args[2],FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){var copies=new List<IntPtr>();try{for(int i=0;i<300;i++){IntPtr copy;Check(DuplicateHandle(GetCurrentProcess(),file.SafeFileHandle.DangerousGetHandle(),GetCurrentProcess(),out copy,0,false,2),"Cannot clone fixture handle");copies.Add(copy);}Console.WriteLine("READY");Console.Out.Flush();Console.ReadLine();}finally{foreach(var copy in copies)CloseHandle(copy);}}return 0;}
  FixtureResult();
  if(args[1]=="stream")Thread.Sleep(700);
  else if(args[1]=="timeout")Thread.Sleep(5000);
  else if(args[1]=="barrier"){File.WriteAllText(args[2],"ready");var watch=Stopwatch.StartNew();while(!File.Exists(args[3])&&watch.ElapsedMilliseconds<4000)Thread.Sleep(10);Check(File.Exists(args[3]),"Independent phases were not running concurrently");}
  Console.WriteLine("DONE\t1\t0");return 0;
 }
 static void Cache(string path){using(var file=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))using(var other=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))using(var cache=new HandleScanner.ProbeCache()){
  IntPtr duplicate;Check(DuplicateHandle(GetCurrentProcess(),file.SafeFileHandle.DangerousGetHandle(),GetCurrentProcess(),out duplicate,0,false,2),"Cannot duplicate test handle");try{cache.Remember(123,7,file.SafeFileHandle.DangerousGetHandle(),path);string hit;Check(cache.TryGet(123,7,duplicate,out hit)&&hit==path,"Same kernel object not cached");Check(!cache.TryGet(123,7,other.SafeFileHandle.DangerousGetHandle(),out hit),"Different file object with the same path reused cached result");Check(!cache.TryGet(123,8,duplicate,out hit),"Different granted access reused cached result");}finally{CloseHandle(duplicate);}}
  Console.WriteLine("PASS: cache compares pinned kernel objects and access rights, rejects distinct opens of the same path");
 }
 static void Workers(string prefix){string exe=Assembly.GetExecutingAssembly().Location;
  using(var received=new ManualResetEvent(false)) {var stream=ScanWorker.RunAsync(exe,"--fixture stream","stream",3000,delegate(string line){if(line.StartsWith("H\t"))received.Set();},null,null);Check(received.WaitOne(2000)&&!stream.IsCompleted,"Results were buffered until phase completion");Check(stream.Result.Completed,"Streaming fixture failed");}
  int results=0;var timeout=ScanWorker.RunAsync(exe,"--fixture timeout","timeout",300,delegate(string line){if(line.StartsWith("H\t"))Interlocked.Increment(ref results);},null,null).Result;Check(timeout.TimedOut&&!timeout.Completed&&results==1,"Timed out phase lost partial results or reported success");
  var first=ScanWorker.RunAsync(exe,"--fixture barrier "+prefix+"-a "+prefix+"-b","first",5000,null,null,null);var second=ScanWorker.RunAsync(exe,"--fixture barrier "+prefix+"-b "+prefix+"-a","second",5000,null,null,null);Task.WaitAll(first,second);Check(first.Result.Completed&&second.Result.Completed,"Independent stages did not overlap");
  var failure=ScanPhaseResult.FromLines("Apple",new[]{"ERROR\t"+HandleScanner.Encode("Npcap missing"),"DONE\t0\t0"});Check(!failure.Completed&&failure.Failure.Contains("Npcap missing"),"Stage error hidden by DONE");Console.WriteLine("PASS: concurrent phases, streaming before completion, timeout retains results, phase-specific errors");
 }
 static void Duplicates(string path,string app){Process holder=null;try{holder=Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--fixture hold "+path){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardInput=true,CreateNoWindow=true});Check(holder.StandardOutput.ReadLine()=="READY","Duplicate fixture not ready");
  var info=new ProcessStartInfo(app,"--scan "+Path.GetPathRoot(path).TrimEnd('\\')){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true};info.EnvironmentVariables["SAFEDETACH_STATS"]="1";using(var scanner=Process.Start(info)){var output=scanner.StandardOutput.ReadToEndAsync();if(!scanner.WaitForExit(25000)){scanner.Kill();scanner.WaitForExit();throw new Exception("Duplicate scan timed out");}int matches=0;foreach(var line in output.Result.Split('\n')){var fields=line.Trim().Split('\t');if(fields.Length==5&&fields[0]=="H"&&fields[1]==holder.Id.ToString()&&HandleScanner.Decode(fields[4])==path)matches++;if(fields[0]=="STATS")Console.WriteLine(line.Trim());}Check(matches==1&&output.Result.Contains("DONE\t"),"Repeated handles changed coverage or duplicated rows");}
  holder.StandardInput.WriteLine("exit");Check(holder.WaitForExit(3000),"Fixture did not stop");Console.WriteLine("PASS: 300 duplicate handles retain real holder detection and one result per path");}finally{if(holder!=null){if(!holder.HasExited){holder.Kill();holder.WaitForExit();}holder.Dispose();}}}
 static void Pump(Task task){var clock=Stopwatch.StartNew();while(!task.IsCompleted&&clock.ElapsedMilliseconds<32000){Application.DoEvents();Thread.Sleep(10);}Check(task.IsCompleted,"UI scan did not finish");task.GetAwaiter().GetResult();}
 static void Window() {
  ExternalDisk disk=null;foreach(var item in Devices.Enumerate())if(!item.IsPortable&&item.Drives.Count>0){disk=item;break;}if(disk==null){Console.WriteLine("SKIP: no external disk for end-to-end scan window");return;}
  Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);var flags=BindingFlags.NonPublic|BindingFlags.Instance;string original=Environment.GetEnvironmentVariable("SAFEDETACH_TEST_MAPPING_FAILURE");
  try {using(var form=new MainWindow(false)) {form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new System.Drawing.Point(-30000,-30000);form.Show();var list=(ListBox)typeof(MainWindow).GetField("disks",flags).GetValue(form);list.Items.Add(disk);list.SelectedIndex=0;
   var scan=typeof(MainWindow).GetMethod("ScanCore",flags);var success=typeof(MainWindow).GetField("scanSucceeded",flags);Pump((Task)scan.Invoke(form,null));Check((bool)success.GetValue(form),"Real parallel UI scan failed");
   Environment.SetEnvironmentVariable("SAFEDETACH_TEST_MAPPING_FAILURE","fail");Pump((Task)scan.Invoke(form,null));var status=(TextBox)typeof(MainWindow).GetField("status",flags).GetValue(form);Check(!(bool)success.GetValue(form)&&status.Text.Contains("内存映射未完成")&&status.Text.Contains("文件句柄已完成"),"UI failed to preserve phase-specific failure/completion");
   Environment.SetEnvironmentVariable("SAFEDETACH_TEST_MAPPING_FAILURE","hang");var pending=(Task)scan.Invoke(form,null);var clock=Stopwatch.StartNew();var workers=typeof(MainWindow).GetField("workers",flags);while(((List<Process>)workers.GetValue(form)).Count==0&&clock.ElapsedMilliseconds<3000){Application.DoEvents();Thread.Sleep(10);}form.Close();Pump(pending);Check(((List<Process>)workers.GetValue(form)).Count==0,"Closing window left scan helpers registered");
  }}finally{Environment.SetEnvironmentVariable("SAFEDETACH_TEST_MAPPING_FAILURE",original);}
  Console.WriteLine("PASS: real parallel UI scan, partial failure names both phases, close during scan cleans helpers");
 }
 [STAThread] static int Main(string[] args){if(args.Length>0&&args[0]=="--fixture")return Fixture(args);if(args.Length>0&&(args[0]=="--scan"||args[0]=="--mapped")){if(args[0]=="--mapped"){string mode=Environment.GetEnvironmentVariable("SAFEDETACH_TEST_MAPPING_FAILURE");if(mode=="fail"){Console.WriteLine("ERROR\t"+HandleScanner.Encode("fixture failure"));Console.WriteLine("DONE\t0\t0");return 0;}if(mode=="hang")Thread.Sleep(30000);}return (int)typeof(MainWindow).Assembly.GetType("SafeDetach.Program").GetMethod("Main",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{args});}string prefix=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"scan-perf-"+Guid.NewGuid().ToString("N"));string path=prefix+".txt";try{File.WriteAllText(path,"fixture");Cache(path);Workers(prefix);Duplicates(path,args[0]);Window();return 0;}catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex.Message);return 1;}finally{foreach(string file in new[]{path,prefix+"-a",prefix+"-b"})if(File.Exists(file))File.Delete(file);}}
}

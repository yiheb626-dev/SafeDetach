using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using SafeDetach;

class DeferredEject {
 static readonly BindingFlags Flags=BindingFlags.Instance|BindingFlags.NonPublic;
 static T Field<T>(MainWindow form,string name){return (T)typeof(MainWindow).GetField(name,Flags).GetValue(form);}
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static void UiContext(){SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());}
 static Task Scan(MainWindow form){UiContext();return (Task)typeof(MainWindow).GetMethod("ScanCore",Flags).Invoke(form,null);}
 static void Wait(Func<bool> done,string message){var clock=Stopwatch.StartNew();while(!done()&&clock.ElapsedMilliseconds<8000){Application.DoEvents();Thread.Sleep(10);}Check(done(),message);Application.DoEvents();}
 static ExternalDisk Disk(string name,string drive){var disk=new ExternalDisk {Name=name,InstanceId=name,Serial=name};disk.Drives.Add(drive);return disk;}
 static string[] Row(int pid,string path){return new[]{"H",pid.ToString(),"100",HandleScanner.Encode("fixture"),HandleScanner.Encode(path)};}
 static void Seed(DeviceScanCache cache,ExternalDisk disk,int pid){DeviceScanCache.Ticket ticket;Check(cache.TryBegin(DeviceScanCache.Key(disk),out ticket),"Seed failed");cache.Finish(ticket,new DeviceScanSnapshot(new[]{Row(pid,"stale")},true,"old","none"));}
 static int Fixture(string[] args){string gate=Environment.GetEnvironmentVariable("SAFEDETACH_EJECT_GATE"),mode=Environment.GetEnvironmentVariable("SAFEDETACH_EJECT_MODE");var clock=Stopwatch.StartNew();while(!File.Exists(gate)&&clock.ElapsedMilliseconds<12000)Thread.Sleep(10);if(!File.Exists(gate))return 1;
  if(mode=="failure"&&args[0]=="--mapped"){Console.WriteLine("ERROR\t"+HandleScanner.Encode("fixture scan failure"));Console.WriteLine("DONE\t0\t0");return 0;}
  if(mode!="empty")Console.WriteLine(string.Join("\t",Row(args[1]=="D:"?12341:12342,"new "+args[1])));Console.WriteLine("DONE\t0\t0");return 0;
 }
 static void Run(string mode,string gate){
  int scans=0,confirmations=0,stops=0,ejections=0;bool other=mode=="other",cancel=mode=="cancel",empty=mode=="empty";int expectedPid=other?12342:12341,expectedScans=other?2:1;
  var a=Disk("A","D:");var b=Disk("B","E:");var selected=other?b:a;var events=new List<string>();
  Environment.SetEnvironmentVariable("SAFEDETACH_EJECT_MODE",mode);Environment.SetEnvironmentVariable("SAFEDETACH_EJECT_GATE",gate);
  using(var form=new MainWindow(false,96,delegate(ExternalDisk disk){Interlocked.Increment(ref scans);return disk;},true)){
   form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new System.Drawing.Point(-30000,-30000);form.Show();
   var cache=Field<DeviceScanCache>(form,"scanCache");if(mode!="first"){Seed(cache,a,111);Seed(cache,b,222);}var list=Field<ListBox>(form,"disks");list.Items.Add(a);list.Items.Add(b);list.SelectedIndex=0;
   Task scan=Scan(form);Wait(delegate{return Field<List<Process>>(form,"workers").Count==2;},"Scan workers did not start");if(other)list.SelectedIndex=1;
   var button=Field<Button>(form,"eject");Check(button.Enabled,"Eject disabled while scanning");
   Func<List<Occupant>,bool> confirm=delegate(List<Occupant> occupants){confirmations++;Check(File.Exists(gate)&&scans==expectedScans,"Confirmation preceded scan completion or caused an unnecessary rescan");Check(occupants.Count==1&&occupants[0].Pid==expectedPid,"Confirmation used stale/wrong-device occupants");Check(!list.Enabled&&Field<bool>(form,"actionInProgress"),"Confirmation did not lock device");typeof(MainWindow).GetMethod("AutomaticScanTick",Flags).Invoke(form,null);Check(scans==expectedScans,"Automatic scan ran during confirmation");if(mode=="confirm-change")cache.Clear();return !cancel;};
   Action<Occupant> terminate=delegate(Occupant occupant){Check(occupant.Pid==expectedPid,"Terminated stale/wrong process");if(mode=="stop-failure")throw new InvalidOperationException("fixture stop failure");stops++;events.Add("stop");};
   Func<ExternalDisk,string> eject=delegate(ExternalDisk disk){Check(DeviceScanCache.Key(disk)==DeviceScanCache.Key(selected),"Ejected wrong device");ejections++;events.Add("eject");return "安全弹出成功：fixture";};
   UiContext();Task request=form.EjectCore(confirm,terminate,eject);Check(!request.IsCompleted&&!list.Enabled&&!button.Enabled&&button.Text=="等待扫描…","Pending eject state incorrect");
   Check(confirmations==0&&stops==0&&ejections==0,"Acted before active scan finished");UiContext();Check(form.EjectCore(confirm,terminate,eject).IsCompleted,"Repeated click queued another request");
   typeof(MainWindow).GetMethod("AutomaticScanTick",Flags).Invoke(form,null);Check(scans==1,"Automatic tick overlapped pending eject");
   if(mode=="invalidate"){cache.Clear();typeof(MainWindow).GetMethod("ShowSelectedDevice",Flags).Invoke(form,null);}
   if(mode=="close")form.Close();else File.WriteAllText(gate,"continue");
   Wait(delegate{return request.IsCompleted&&scan.IsCompleted;},"Deferred eject never completed");request.GetAwaiter().GetResult();scan.GetAwaiter().GetResult();
   if(mode=="failure"||mode=="invalidate"||mode=="close"){
    Check(confirmations==0&&stops==0&&ejections==0,"Failed/invalidated/closed scan proceeded to eject");
    if(mode!="close")Check(Field<TextBox>(form,"status").Visible,"Cancelled eject did not show error");
   }else if(cancel||mode=="confirm-change"||mode=="stop-failure"){
    Check(confirmations==1&&stops==0&&ejections==0,"Cancelled/changed/failed release still ejected");
    if(mode!="cancel")Check(Field<TextBox>(form,"status").Visible,"Action failure did not show error");
   }else Check(confirmations==(empty?0:1)&&stops==(empty?0:1)&&ejections==1&&string.Join(",",events.ToArray())==(empty?"eject":"stop,eject"),"Successful action order/count incorrect");
   Check(!Field<bool>(form,"actionInProgress")&&!Field<bool>(form,"waitingToEject"),"Pending state not released");
   if(mode!="close"){Check(list.Enabled&&button.Text!="等待扫描…","Controls did not recover");if(cancel){UiContext();typeof(MainWindow).GetMethod("AutomaticScanTick",Flags).Invoke(form,null);Wait(delegate{return !Field<bool>(form,"busy");},"Automatic scan did not resume after cancel");Check(scans==2,"Automatic scan remained paused");}form.Close();}
  }
  if(File.Exists(gate))File.Delete(gate);Console.WriteLine("PASS: deferred eject "+mode);
 }
 [STAThread] static int Main(string[] args){if(args.Length==2&&(args[0]=="--scan"||args[0]=="--mapped"))return Fixture(args);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string gate=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"eject-"+Guid.NewGuid().ToString("N")+".gate");string previousGate=Environment.GetEnvironmentVariable("SAFEDETACH_EJECT_GATE"),previousMode=Environment.GetEnvironmentVariable("SAFEDETACH_EJECT_MODE");try{foreach(string mode in new[]{"same","other","first","empty","cancel","failure","invalidate","confirm-change","stop-failure","close"})Run(mode,gate);return 0;}catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex.Message);return 1;}finally{Environment.SetEnvironmentVariable("SAFEDETACH_EJECT_GATE",previousGate);Environment.SetEnvironmentVariable("SAFEDETACH_EJECT_MODE",previousMode);if(File.Exists(gate))File.Delete(gate);}}
}

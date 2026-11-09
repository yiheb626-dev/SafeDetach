using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using SafeDetach;

class AutomaticScan {
 static readonly BindingFlags Flags=BindingFlags.Instance|BindingFlags.NonPublic;
 static T Field<T>(MainWindow form,string name){return (T)typeof(MainWindow).GetField(name,Flags).GetValue(form);}
 static object Call(MainWindow form,string name,params object[] args){return typeof(MainWindow).GetMethod(name,Flags).Invoke(form,args);}
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static string[] Row(int pid,string path,long started=100){return new[]{"H",pid.ToString(),started.ToString(),HandleScanner.Encode("fixture"),HandleScanner.Encode(path)};}
 static DeviceScanSnapshot Snapshot(string label,int pid,bool complete=true){return new DeviceScanSnapshot(new[]{Row(pid,label)},complete,label,complete?"none":"partial");}
 static ExternalDisk Device(string instance,string serial,string drive){var result=new ExternalDisk {InstanceId=instance,Serial=serial,Name=instance};result.Drives.Add(drive);return result;}
 static void Seed(DeviceScanCache cache,ExternalDisk disk,DeviceScanSnapshot snapshot){DeviceScanCache.Ticket ticket;Check(cache.TryBegin(DeviceScanCache.Key(disk),out ticket),"Cannot seed cache");Check(cache.Finish(ticket,snapshot),"Cannot commit seed");}
 static void Store(){
  var a=Device("A","1","D:");var b=Device("B","2","E:");string ka=DeviceScanCache.Key(a),kb=DeviceScanCache.Key(b);var cache=new DeviceScanCache();DeviceScanCache.Ticket first,blocked;
  Check(cache.TryBegin(ka,out first)&&!cache.TryBegin(kb,out blocked),"Overlapping scan admitted");cache.Preview(first,Snapshot("partial A",1,false));Check(cache.Get(ka).Rows.Length==1&&cache.Get(kb)==null,"Preview leaked to another device");cache.Finish(first,Snapshot("good A",1));Seed(cache,b,Snapshot("good B",2));var old=cache.Get(ka);
  DeviceScanCache.Ticket update;Check(cache.TryBegin(ka,out update),"Cannot start update");cache.Preview(update,Snapshot("new provisional A",3,false));Check(cache.Get(ka).Rows[0][1]=="1","Refresh replaced good rows prematurely");cache.Finish(update,new DeviceScanSnapshot(new[]{Row(3,"timeout A")},false,"timeout A","partial",hasError:true));Check(cache.Get(ka).Rows[0][1]=="1"&&!cache.Get(ka).Completed&&cache.Get(ka).Updated==old.Updated&&cache.Get(ka).HasError&&cache.Get(kb).Rows[0][1]=="2","Partial failure mixed/replaced good results or changed another device");
  Check(cache.TryBegin(ka,out update),"Cannot retry");cache.Finish(update,new DeviceScanSnapshot(new string[0][],true,"empty","empty"));Check(cache.Get(ka).Rows.Length==0,"Successful empty scan retained stale occupants");
  DeviceScanCache.Ticket stale,newer;cache.TryBegin(ka,out stale);cache.Clear();Check(!cache.Finish(stale,Snapshot("stale",9))&&cache.Get(ka)==null,"Disconnected scan restored invalid cache");cache.TryBegin(kb,out newer);Check(!cache.Finish(stale,Snapshot("late stale",9))&&cache.IsCurrent(newer),"Old completion unlocked a newer run");cache.Finish(newer,Snapshot("new B",2));
  Seed(cache,a,Snapshot("old A",1));cache.Prune(new[]{a});Check(cache.Get(ka)!=null&&cache.Get(kb)==null,"Prune did not preserve connected device");Check(cache.Get(DeviceScanCache.Key(Device("A","changed","D:")))==null,"Changed serial reused old cache");
  var source=Row(7,"immutable");var frozen=new DeviceScanSnapshot(new[]{source},true,"good","none");source[1]="99";Check(frozen.Rows[0][1]=="7","Snapshot shares mutable result buffer");
  Seed(cache,b,new DeviceScanSnapshot(new[]{Row(7,"old",100),Row(7,"reused",200)},true,"both","none"));cache.RemoveProcess(7,100);Check(cache.Get(kb).Rows.Length==1&&cache.Get(kb).Rows[0][2]=="200","PID reuse removed the wrong cached process");Check(cache.Get(ka).Completed&&cache.Get(ka).Rows[0][1]=="1","Stopping a process changed an unrelated device cache");
  Console.WriteLine("PASS: per-device snapshots, one active run, atomic refresh, failed refresh retains good data, stale completion/identity/PID guards");
 }
 static void Wait(Func<bool> condition,string message,int timeout=10000,Action observe=null){var watch=Stopwatch.StartNew();while(!condition()&&watch.ElapsedMilliseconds<timeout){Application.DoEvents();if(observe!=null)observe();Thread.Sleep(10);}Check(condition(),message);Application.DoEvents();}
 static void ContainsOnly(MainWindow form,int pid){var rows=Field<DataGridView>(form,"table").Rows;Check(rows.Count==1&&Convert.ToString(rows[0].Cells[1].Value)==pid.ToString(),"Selected device displays another device's rows");}
 static void Ui(string gate){
  var a=Device("A","1","D:");var b=Device("B","2","E:");int starts=0;
  using(var form=new MainWindow(false,96,delegate(ExternalDisk disk){Interlocked.Increment(ref starts);return disk;},true)){
   form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new System.Drawing.Point(-30000,-30000);form.Show();var cache=Field<DeviceScanCache>(form,"scanCache");var list=Field<ListBox>(form,"disks");Seed(cache,a,Snapshot("old A",111));Seed(cache,b,Snapshot("old B",222));list.Items.Add(a);list.Items.Add(b);list.SelectedIndex=0;ContainsOnly(form,111);list.SelectedIndex=1;ContainsOnly(form,222);list.SelectedIndex=0;ContainsOnly(form,111);
   Environment.SetEnvironmentVariable("SAFEDETACH_AUTOSCAN_GATE",gate);var pending=(Task)Call(form,"ScanCore");Wait(delegate{return starts==1;},"Initial scan not started");Check(list.Enabled,"Device switching disabled throughout background scan");ContainsOnly(form,111);
   var spinner=Field<ScanSpinner>(form,"scanSpinner");var status=Field<TextBox>(form,"status");Check(spinner.Running&&spinner.Visible,"Selected active scan has no spinner");
   Wait(delegate{return (float)typeof(ScanSpinner).GetField("angle",Flags).GetValue(spinner)!=0;},"Spinner does not animate",1000);
   list.SelectedIndex=1;ContainsOnly(form,222);Check(!spinner.Running&&!spinner.Visible,"Another device shows previous scan's spinner");Check(!status.Visible&&status.Text.Length==0,"Normal status remains visible");
   list.SelectedIndex=0;Check(spinner.Running,"Returning to active device did not resume spinner");list.SelectedIndex=1;
   var timer=Field<System.Windows.Forms.Timer>(form,"autoScanTimer");Check(timer.Interval==15000,"Automatic period is not 15 seconds");timer.Start();var watch=Stopwatch.StartNew();while(watch.ElapsedMilliseconds<15300){Application.DoEvents();ContainsOnly(form,222);Thread.Sleep(10);}timer.Stop();Check(starts==1&&!pending.IsCompleted,"15-second tick overlapped the slow scan");
   File.WriteAllText(gate,"continue");Wait(delegate{return pending.IsCompleted&&starts==2&&!Field<bool>(form,"busy");},"Latest selected device was not scanned after previous run",10000,delegate{var table=Field<DataGridView>(form,"table");foreach(DataGridViewRow row in table.Rows)Check(Convert.ToString(row.Cells[1].Value)!="12341","Late A result overwrote selected B");});pending.GetAwaiter().GetResult();ContainsOnly(form,12342);Check(!spinner.Running&&!status.Visible,"Finished scan retained spinner/status");
   list.SelectedIndex=0;ContainsOnly(form,12341);list.SelectedIndex=1;ContainsOnly(form,12342);
   typeof(MainWindow).GetField("actionInProgress",Flags).SetValue(form,true);Call(form,"AutomaticScanTick");Application.DoEvents();Check(starts==2,"Automatic scan ran during a critical action");typeof(MainWindow).GetField("actionInProgress",Flags).SetValue(form,false);
   // Consume the last queued selection request explicitly, then invalidate its cache.
   File.Delete(gate);var late=(Task)Call(form,"ScanCore");Wait(delegate{return starts==3;},"Late scan not started");cache.Clear();Call(form,"ShowSelectedDevice");Check(Field<DataGridView>(form,"table").Rows.Count==0,"Invalidation did not clear displayed rows");Check(!spinner.Running,"Invalidation retained spinner");File.WriteAllText(gate,"continue");Wait(delegate{return late.IsCompleted;},"Invalidated scan did not finish");late.GetAwaiter().GetResult();Check(cache.Get(DeviceScanCache.Key(b))==null&&Field<DataGridView>(form,"table").Rows.Count==0,"Invalidated scan repopulated rows");
   form.Close();Check(!spinner.Running,"Closing retained spinner");Check(!timer.Enabled,"Closing window did not stop automatic timer");
  }
  Console.WriteLine("PASS: real 15-second tick skips busy run, switching retains rows, late results isolated, selected device queued once, critical pause and invalidation");
 }
 static int Fixture(string[] args){string gate=Environment.GetEnvironmentVariable("SAFEDETACH_AUTOSCAN_GATE");var watch=Stopwatch.StartNew();while(!string.IsNullOrEmpty(gate)&&!File.Exists(gate)&&watch.ElapsedMilliseconds<22000)Thread.Sleep(10);int pid=args[1].StartsWith("D:",StringComparison.OrdinalIgnoreCase)?12341:12342;Console.WriteLine(string.Join("\t",Row(pid,"new "+args[1])));Console.WriteLine("DONE\t1\t0");return 0;}
 [STAThread] static int Main(string[] args){if(args.Length>0&&(args[0]=="--scan"||args[0]=="--mapped"))return Fixture(args);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string gate=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"auto-scan-"+Guid.NewGuid().ToString("N")+".gate");string old=Environment.GetEnvironmentVariable("SAFEDETACH_AUTOSCAN_GATE");try{Store();Ui(gate);return 0;}catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex.Message);return 1;}finally{Environment.SetEnvironmentVariable("SAFEDETACH_AUTOSCAN_GATE",old);if(File.Exists(gate))File.Delete(gate);}}
}

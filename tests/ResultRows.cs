using System;
using System.Reflection;
using System.Windows.Forms;
using System.Drawing;
using System.Collections.Generic;
using SafeDetach;
class ResultRows {
 [STAThread] static int Main(string[] args) {
  Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
  using(var form=new MainWindow(false)) {
   var flags=BindingFlags.Instance|BindingFlags.NonPublic;
   var list=(ListBox)typeof(MainWindow).GetField("disks",flags).GetValue(form);
   var eject=(Button)typeof(MainWindow).GetField("eject",flags).GetValue(form);
   var disk=new ExternalDisk {Name="Lexar ES3",InstanceId="fixture-es3",Serial="fixture"};disk.Drives.Add("H:");list.Items.Add(disk);list.Items.Add(new ExternalDisk {Name="Apple iPhone",IsPortable=true,InstanceId="fixture-phone"});list.SelectedIndex=0;
   if(eject.Text!="安全弹出")throw new Exception("Empty list must show safe eject");
   if(args.Length==1){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-30000,-30000);form.Show();}
   var add=typeof(MainWindow).GetMethod("AddResult",BindingFlags.Instance|BindingFlags.NonPublic);
   var table=(DataGridView)typeof(MainWindow).GetField("table",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(form);
   Action<string,string> insert=delegate(string start,string path) {add.Invoke(form,new object[]{new[]{"H","1234",start,HandleScanner.Encode("TestViewer"),HandleScanner.Encode(path)}});};
   insert("100","H:\\照片\\one.jpg");insert("100","H:\\照片\\one.jpg");insert("100","H:\\照片\\two.jpg");
   if(table.Rows.Count!=1)throw new Exception("One process must occupy one row");
   if(eject.Text!="强制弹出")throw new Exception("Occupied list must show force eject");
   if(table.Rows[0].Cells[2].ToolTipText.Split('\n').Length!=2)throw new Exception("Duplicate paths must be deduplicated");
   if(!Convert.ToString(table.Rows[0].Cells[2].Value).Contains("2"))throw new Exception("Path count missing");
   insert("200","H:\\new.jpg");if(table.Rows.Count!=2)throw new Exception("PID reuse must preserve identity");
   var events=new List<string>();var target=new Occupant {Pid=1234,Started=100,Name="fixture"};
   EjectWorkflow.ReleaseAndEject(disk,new[]{target,target},delegate(Occupant p){events.Add("stop");},delegate(ExternalDisk d){events.Add("eject");return "ok";});
   if(string.Join(",",events.ToArray())!="stop,eject")throw new Exception("Force flow ordering/deduplication");
   events.Clear();EjectWorkflow.ReleaseAndEject(disk,new Occupant[0],delegate(Occupant p){throw new Exception("Unexpected termination");},delegate(ExternalDisk d){events.Add("eject");return "ok";});if(events.Count!=1)throw new Exception("Safe eject flow");
   events.Clear();try{EjectWorkflow.ReleaseAndEject(disk,new[]{target},delegate(Occupant p){throw new InvalidOperationException("denied");},delegate(ExternalDisk d){events.Add("eject");return "bad";});throw new Exception("Expected failure");}catch(InvalidOperationException){}if(events.Count!=0)throw new Exception("Must not eject after termination fails");
   try{EjectWorkflow.ReleaseAndEject(disk,new[]{target,new Occupant {Pid=4,Started=1}},delegate(Occupant p){events.Add("stop");},delegate(ExternalDisk d){return "bad";});throw new Exception("Expected invalid target rejection");}catch(InvalidOperationException){}if(events.Count!=0)throw new Exception("Must validate all targets before stopping any");
   Console.WriteLine("PASS: aggregation, button states, safe/force ordering, failure handling, target validation");
   if(args.Length==1) {
    table.Rows.RemoveAt(1);
    var status=(TextBox)typeof(MainWindow).GetField("status",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(form);status.Text="检测到 1 个占用进程。";
    form.CreateControl();form.PerformLayout();using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(args[0]);}
    table.Rows.Clear();if(eject.Text!="安全弹出")throw new Exception("Clearing occupancy must restore safe eject");status.Text="未检测到占用进程。";((Label)typeof(MainWindow).GetField("empty",flags).GetValue(form)).Text="没有检测到占用进程";
    form.Size=form.MinimumSize;form.PerformLayout();using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(System.IO.Path.ChangeExtension(args[0],"empty.png"));}
   }
   return 0;
  }
 }
}

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
   form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-30000,-30000);form.Show();
   var render=typeof(MainWindow).GetMethod("RenderSnapshot",flags);var footer=(TextBox)typeof(MainWindow).GetField("status",flags).GetValue(form);
   render.Invoke(form,new object[]{new DeviceScanSnapshot(new string[0][],true,"部分进程无访问权限。（结果时间 10:05:10）","none")});
   if(footer.Visible||footer.Text.Length!=0)throw new Exception("Normal footer must be hidden");
   render.Invoke(form,new object[]{new DeviceScanSnapshot(new string[0][],false,"扫描失败：fixture","failed",hasError:true)});
   if(!footer.Visible||footer.Text!="扫描失败：fixture")throw new Exception("Error footer missing");
   render.Invoke(form,new object[]{new DeviceScanSnapshot(new string[0][],false,"正在扫描…","scanning")});
   if(footer.Visible||footer.Text.Length!=0)throw new Exception("Non-error incomplete status is visible");
   Console.WriteLine("PASS: footer appears only for explicit errors and clears on retry");
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
   var mobile=new ExternalDisk {Name="Apple iPad",IsPortable=true};if(DeviceList.Detail(mobile).Contains("手机")||!DeviceList.Detail(mobile).Contains("移动设备")||mobile.ToString().Contains("手机"))throw new Exception("Tablet must use neutral mobile-device label");
   var sockets=new List<AppleServiceScanner.Connection>{new AppleServiceScanner.Connection {State=2,LocalAddress=0x0100007f,LocalPort=27015,Pid=100},new AppleServiceScanner.Connection {State=5,LocalAddress=0x0100007f,RemoteAddress=0x0100007f,LocalPort=50000,RemotePort=27015,Pid=200},new AppleServiceScanner.Connection {State=5,LocalAddress=0x0100007f,RemoteAddress=0x0100007f,LocalPort=27015,RemotePort=50000,Pid=100}};
   if(AppleServiceScanner.Clients(sockets,100,300).Count!=1)throw new Exception("Apple service client not matched");
   if(AppleServiceScanner.Clients(sockets,101,300).Count!=0||AppleServiceScanner.Clients(sockets,100,200).Count!=0)throw new Exception("Wrong service/self exclusion failed");
   sockets[1].State=11;if(AppleServiceScanner.Clients(sockets,100,300).Count!=0)throw new Exception("Closed TCP connection reported");sockets[1].State=5;sockets.RemoveAt(2);if(AppleServiceScanner.Clients(sockets,100,300).Count!=0)throw new Exception("Unpaired connection reported");
   if(!AppleServiceScanner.MatchesSingle(new List<string>{"AABB"},"aa-bb")||AppleServiceScanner.MatchesSingle(new List<string>{"AABB"},"other")||AppleServiceScanner.MatchesSingle(new List<string>{"AABB","CCDD"},"AABB"))throw new Exception("Apple device ambiguity guard failed");
   Console.WriteLine("PASS: mobile label, verified Apple endpoint pairs, closed/self/wrong-service rejection, multi-device guard");
   var setSupport=typeof(MainWindow).GetMethod("SetNpcapNotice",flags);
   var support=(Panel)typeof(MainWindow).GetField("npcapNotice",flags).GetValue(form);
   var download=(Button)typeof(MainWindow).GetField("npcapDownload",flags).GetValue(form);
   var retry=(Button)typeof(MainWindow).GetField("npcapRetry",flags).GetValue(form);
   var content=(TableLayoutPanel)typeof(MainWindow).GetField("content",flags).GetValue(form);
   setSupport.Invoke(form,new object[]{true,false});form.PerformLayout();
   if(content.RowStyles[1].Height<=0||download.Text!="前往官网下载"||retry.Text!="安装后重试")throw new Exception("Missing Npcap actions unavailable");
   var official=new Uri(NpcapSupport.DownloadUrl);if(official.Scheme!="https"||official.Host!="npcap.com"||official.AbsolutePath!="/")throw new Exception("Download must open the official page");
   typeof(MainWindow).GetMethod("Busy",flags).Invoke(form,new object[]{true});if(retry.Enabled)throw new Exception("Retry must not replace monitor while scanning");typeof(MainWindow).GetMethod("Busy",flags).Invoke(form,new object[]{false});
   setSupport.Invoke(form,new object[]{true,true});if(retry.Text!="重新启用识别")throw new Exception("Installed but unavailable Npcap cannot be retried");
   setSupport.Invoke(form,new object[]{false,true});if(content.RowStyles[1].Height!=0)throw new Exception("Installed Npcap notice must collapse");
   Console.WriteLine("PASS: missing/install-retry states, official HTTPS destination, busy guard and collapsed layout");
   if(args.Length==1) {
    table.Rows.RemoveAt(1);
    var status=(TextBox)typeof(MainWindow).GetField("status",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(form);status.Text="检测到 1 个占用进程。";
    form.CreateControl();form.PerformLayout();using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(args[0]);}
    table.Rows.Clear();if(eject.Text!="安全弹出")throw new Exception("Clearing occupancy must restore safe eject");status.Text="未检测到占用进程。";((Label)typeof(MainWindow).GetField("empty",flags).GetValue(form)).Text="没有检测到占用进程";
    form.Size=form.MinimumSize;form.PerformLayout();using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(System.IO.Path.ChangeExtension(args[0],"empty.png"));}
    setSupport.Invoke(form,new object[]{true,false});form.PerformLayout();
    var vp=(Panel)typeof(MainWindow).GetField("viewport",flags).GetValue(form);if(vp.AutoScrollPosition!=Point.Empty||vp.HorizontalScroll.Visible||vp.VerticalScroll.Visible)throw new Exception("Minimum window has unnecessary scrolling or shifted content");
    if(!support.Visible||!download.Visible||!retry.Visible||download.Height<24||retry.Height<24)throw new Exception("Npcap actions clipped at minimum window size");
    var noticeBounds=support.RectangleToScreen(support.ClientRectangle);if(!noticeBounds.Contains(download.RectangleToScreen(download.ClientRectangle))||!noticeBounds.Contains(retry.RectangleToScreen(retry.ClientRectangle)))throw new Exception("Npcap actions overflow notice");
    using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(System.IO.Path.ChangeExtension(args[0],"npcap.png"));}
   }
   return 0;
  }
 }
}

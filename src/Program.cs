using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SafeDetach {
 static class Program {
  [STAThread] static int Main(string[] args) {
   Environment.CurrentDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   if(args.Length==3 && args[0]=="--handle-name")return HandleScanner.QuerySingle(int.Parse(args[1]),long.Parse(args[2]));
   if(args.Length==2 && args[0]=="--portable") {try{string instance=HandleScanner.Decode(args[1]);var reference=PortableTargets.Reference(instance);foreach(var other in Devices.Enumerate())if(other.IsPortable&&other.InstanceId!=instance&&PortableTargets.Reference(other.InstanceId).Key==reference.Key)throw new InvalidOperationException("设备身份重复，无法区分手机。");HandleScanner.SelectedPortableIdentity=reference;return HandleScanner.Run(new[]{"WPD:"+reference.Key},true);}catch(Exception ex){Console.WriteLine("ERROR\t"+HandleScanner.Encode(ex.Message));return 1;}}
   if(args.Length>0 && args[0]=="--windows") {var roots=new string[args.Length-1];Array.Copy(args,1,roots,0,roots.Length);return WindowClueScanner.Run(roots);}
   if(args.Length>0 && args[0]=="--mapped") {var roots=new string[args.Length-1];Array.Copy(args,1,roots,0,roots.Length);return MappedFileScanner.Run(roots);}
   if(args.Length>0 && args[0]=="--scan") { var roots=new string[args.Length-1]; Array.Copy(args,1,roots,0,roots.Length); return HandleScanner.Run(roots); }
   Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); Application.Run(new MainWindow()); return 0;
  }
 }
 public sealed class MainWindow:Form {
  DeviceList disks=new DeviceList(); DataGridView table=new DataGridView(); TextBox status=new TextBox {Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.None,BorderStyle=BorderStyle.None,BackColor=Color.White,TabStop=false};
  Label deviceTitle=new Label(),deviceDetail=new Label(),processCount=new Label(),empty=new Label(); bool scanSucceeded;
  Button refresh=new Button(), scan=new Button(), eject=new Button(), elevate=new Button(); bool busy;
  readonly bool autoScan; Process helper;bool closing;bool deviceChangePending;readonly Timer deviceTimer=new Timer {Interval=800};
  public MainWindow():this(true) {}
  public MainWindow(bool loadDevices) {
   autoScan=loadDevices;
   AutoScaleDimensions=new SizeF(96,96); AutoScaleMode=AutoScaleMode.Dpi; Text="SafeDetach 1.3.1"; Size=new Size(1120,720); MinimumSize=new Size(940,560); StartPosition=FormStartPosition.CenterScreen;
   Font=new Font("Microsoft YaHei UI",10); BackColor=Color.White; ForeColor=Color.FromArgb(30,41,59);
   var shell=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,250));shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
   var sidebar=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(18,24,18,18),ColumnCount=1,RowCount=5,BackColor=Color.FromArgb(245,247,250),Margin=Padding.Empty};
   foreach(float height in new float[]{88,30})sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,height));sidebar.RowStyles.Add(new RowStyle(SizeType.Percent,100));sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,44));sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,50));
   sidebar.Controls.Add(new Label {Name="brandName",Text="Safe\nDetach",Font=new Font(Font.FontFamily,18,FontStyle.Bold),ForeColor=Color.FromArgb(14,116,99),Dock=DockStyle.Fill},0,0);
   sidebar.Controls.Add(new Label {Text="外接设备",ForeColor=Color.FromArgb(100,116,139),Dock=DockStyle.Fill},0,1);
   disks.Dock=DockStyle.Fill;sidebar.Controls.Add(disks,0,2);
   disks.SelectedIndexChanged+=delegate {scanSucceeded=false;table.Rows.Clear();var selected=disks.SelectedItem as ExternalDisk;deviceTitle.Text=selected==null?"选择设备":DeviceList.Title(selected);deviceDetail.Text=selected==null?"从左侧选择要管理的设备":DeviceList.Detail(selected);empty.Text="尚未扫描\n点击右上角扫描占用";status.Text=selected==null?"请连接外接设备。":"就绪";Busy(busy);if(autoScan&&selected!=null&&!busy&&IsHandleCreated)BeginInvoke((Action)delegate {if(!closing&&!busy&&disks.SelectedItem==selected)Scan();});};
   StyleButton(elevate,"管理员模式",false,delegate {try {Process.Start(new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas",WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows)});Close();}catch(Exception ex){status.Text=ex.Message;}});elevate.Dock=DockStyle.Fill;sidebar.Controls.Add(elevate,0,3);
   elevate.Visible=!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
   StyleButton(refresh,"刷新设备",false,delegate {RefreshDevices();});refresh.Dock=DockStyle.Fill;sidebar.Controls.Add(refresh,0,4);
   var content=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(28,26,28,20),RowCount=4,ColumnCount=1,Margin=Padding.Empty};content.RowStyles.Add(new RowStyle(SizeType.Absolute,86));content.RowStyles.Add(new RowStyle(SizeType.Absolute,52));content.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.RowStyles.Add(new RowStyle(SizeType.Absolute,82));
   var heading=new TableLayoutPanel {Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,Margin=Padding.Empty};heading.RowStyles.Add(new RowStyle(SizeType.Absolute,42));heading.RowStyles.Add(new RowStyle(SizeType.Percent,100));deviceTitle.Text="选择设备";deviceTitle.Font=new Font(Font.FontFamily,20,FontStyle.Bold);deviceTitle.Dock=DockStyle.Fill;deviceTitle.AutoEllipsis=true;deviceDetail.Dock=DockStyle.Fill;deviceDetail.ForeColor=Color.FromArgb(100,116,139);deviceDetail.Text="从左侧选择要管理的设备";heading.Controls.Add(deviceTitle,0,0);heading.Controls.Add(deviceDetail,0,1);content.Controls.Add(heading,0,0);
   var tools=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};tools.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,124));processCount.Text="占用进程 · 0";processCount.Dock=DockStyle.Fill;processCount.TextAlign=ContentAlignment.MiddleLeft;processCount.Font=new Font(Font,FontStyle.Bold);tools.Controls.Add(processCount,0,0);StyleButton(scan,"扫描占用",false,delegate {Scan();});scan.Dock=DockStyle.Fill;tools.Controls.Add(scan,1,0);content.Controls.Add(tools,0,1);
   table.ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.DisableResizing;table.ColumnHeadersHeight=42;table.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.None;table.RowTemplate.Height=46;table.Dock=DockStyle.Fill;table.ReadOnly=true;table.AllowUserToAddRows=false;table.AllowUserToDeleteRows=false;table.RowHeadersVisible=false;table.BackgroundColor=Color.White;table.BorderStyle=BorderStyle.None;table.CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal;table.GridColor=Color.FromArgb(237,241,245);table.EnableHeadersVisualStyles=false;table.ColumnHeadersBorderStyle=DataGridViewHeaderBorderStyle.None;table.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(248,250,252);table.ColumnHeadersDefaultCellStyle.ForeColor=Color.FromArgb(100,116,139);table.ColumnHeadersDefaultCellStyle.Padding=new Padding(10,0,0,0);table.DefaultCellStyle.Padding=new Padding(10,0,0,0);table.DefaultCellStyle.SelectionBackColor=Color.FromArgb(233,245,241);table.DefaultCellStyle.SelectionForeColor=ForeColor;table.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;table.SelectionMode=DataGridViewSelectionMode.FullRowSelect;
   table.Columns.Add("name","程序 / 进程"); table.Columns.Add("pid","PID"); table.Columns.Add("path","占用内容");
   table.Columns[0].FillWeight=25; table.Columns[1].FillWeight=10; table.Columns[2].FillWeight=55;
   table.Columns.Add(new DataGridViewButtonColumn {Name="stop",HeaderText="",Text="结束进程",UseColumnTextForButtonValue=true,FlatStyle=FlatStyle.Flat,FillWeight=23});table.Columns[1].FillWeight=14;table.CellContentClick+=StopClicked;
   table.CellPainting+=delegate(object sender,DataGridViewCellPaintingEventArgs e){if(e.RowIndex>=0&&e.ColumnIndex==3){e.PaintBackground(e.ClipBounds,true);TextRenderer.DrawText(e.Graphics,"结束进程",Font,e.CellBounds,Color.FromArgb(170,65,47),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);e.Handled=true;}};
   var listHost=new Panel {Dock=DockStyle.Fill,Margin=Padding.Empty};listHost.Controls.Add(table);empty.Dock=DockStyle.Fill;empty.Text="尚未扫描\n选择设备后扫描占用";empty.TextAlign=ContentAlignment.MiddleCenter;empty.ForeColor=Color.FromArgb(148,163,184);empty.Font=new Font(Font.FontFamily,12);listHost.Controls.Add(empty);content.Controls.Add(listHost,0,2);
   var footer=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Padding=new Padding(0,18,0,0),Margin=Padding.Empty};footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,150));status.Dock=DockStyle.Fill;status.Margin=new Padding(0,4,16,0);status.Text="正在读取设备…";status.ForeColor=Color.FromArgb(100,116,139);footer.Controls.Add(status,0,0);StyleButton(eject,"安全弹出",true,delegate {Eject();});eject.Dock=DockStyle.Top;eject.Height=46;footer.Controls.Add(eject,1,0);content.Controls.Add(footer,0,3);
   shell.Controls.Add(sidebar,0,0);shell.Controls.Add(content,1,0);Controls.Add(shell);table.RowsAdded+=delegate {UpdateResults();};table.RowsRemoved+=delegate {UpdateResults();};UpdateResults();Busy(false);
   deviceTimer.Tick+=delegate {if(!busy&&deviceChangePending){deviceChangePending=false;deviceTimer.Stop();RefreshDevices();}};
   Shown+=delegate {if(loadDevices)RefreshDevices();}; FormClosing+=delegate {closing=true;deviceTimer.Stop();try{if(helper!=null&&!helper.HasExited)helper.Kill();}catch{}};FormClosed+=delegate{deviceTimer.Dispose();};
  }
  protected override void WndProc(ref Message message) {base.WndProc(ref message);if(message.Msg==0x219&&!closing){deviceChangePending=true;deviceTimer.Start();}}
  void StyleButton(Button button,string text,bool primary,EventHandler handler) {button.Text=text;button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderSize=primary?0:1;button.FlatAppearance.BorderColor=Color.FromArgb(220,227,234);button.BackColor=primary?Color.FromArgb(14,116,99):Color.White;button.ForeColor=primary?Color.White:ForeColor;button.Cursor=Cursors.Hand;button.Height=40;button.Margin=new Padding(0,4,0,4);button.Click+=handler;}
  void UpdateResults() {bool occupied=table.Rows.Count>0;eject.Text=occupied?"强制弹出":"安全弹出";eject.BackColor=occupied?Color.FromArgb(185,83,42):Color.FromArgb(14,116,99);processCount.Text="占用进程 · "+table.Rows.Count;empty.Visible=!occupied;}
  void Busy(bool value) {busy=value;if(closing)return;refresh.Enabled=disks.Enabled=elevate.Enabled=!value;scan.Enabled=eject.Enabled=!value&&disks.SelectedItem!=null;UpdateResults();}
  async void RefreshDevices() {
   if(busy)return;Busy(true);table.Rows.Clear();
   string selectedId=(disks.SelectedItem as ExternalDisk)==null?null:((ExternalDisk)disks.SelectedItem).InstanceId;
   try {var items=await Task.Factory.StartNew(delegate {return Devices.Enumerate();});if(closing)return;disks.Items.Clear();foreach(var disk in items)disks.Items.Add(disk);if(items.Count>0){disks.SelectedIndex=0;foreach(var disk in items)if(disk.InstanceId==selectedId)disks.SelectedItem=disk;}else status.Text="未发现 USB 存储或手机设备。连接后会自动刷新，也可点击刷新设备。";}catch(Exception ex){if(!closing)status.Text="读取设备失败："+ex.Message;}finally{Busy(false);}if(autoScan&&!closing&&disks.SelectedItem!=null)Scan();
  }
  async void Scan() {
   await ScanCore();
  }
  async Task ScanCore() {
   var disk=disks.SelectedItem as ExternalDisk;if(busy||disk==null)return;
   if(!disk.IsPortable&&disk.Drives.Count==0){status.Text="设备没有盘符。";return;}
   scanSucceeded=false;Busy(true);table.Rows.Clear();empty.Text="正在扫描…";status.Text="正在扫描占用…";
   try {
    var current=await Task.Factory.StartNew( delegate {return Devices.Enumerate();});
    if(closing)return;
    ExternalDisk verified=null;foreach(var candidate in current)if(candidate.InstanceId==disk.InstanceId&&candidate.Serial==disk.Serial)verified=candidate;
    if(verified==null){status.Text="设备已断开，请刷新设备。";return;}disk=verified;
    if(!disk.IsPortable&&disk.Drives.Count==0){status.Text="设备没有盘符。";return;}
    bool incomplete=false;int denied=0;string failure="";
    foreach(string mode in disk.IsPortable?new[]{"--portable"}:new[]{"--scan","--mapped"}) {
    if(closing)return;
    string phase=mode=="--scan"?"文件句柄":mode=="--mapped"?"文件映射":"设备连接";
    status.Text="正在扫描"+phase+"，本阶段最长 25 秒…";
    var info=new ProcessStartInfo(Application.ExecutablePath,mode+" "+(disk.IsPortable?HandleScanner.Encode(disk.InstanceId):string.Join(" ",disk.Drives.ToArray()))) {UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true,WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows)};
    using(var child=new Process {StartInfo=info}) {
     helper=child;bool completed=false;string detail="";var lines=new List<string>();
     child.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data!=null)lock(lines)lines.Add(e.Data);};
     child.Start();child.BeginOutputReadLine();
     bool exited=await Task.Factory.StartNew(delegate {return child.WaitForExit(25000);});
     if(!exited){try{child.Kill();}catch(InvalidOperationException){}} await Task.Factory.StartNew(delegate {child.WaitForExit();});
     if(closing)return;
     foreach(string line in lines) {
      string[] p=line.Split('\t');
      if((p[0]=="H"||p[0]=="M")&&p.Length==5) AddResult(p);
      else if(p[0]=="DONE") {completed=true;denied=Math.Max(denied,int.Parse(p[2]));}
      else if(p[0]=="ERROR")detail=HandleScanner.Decode(p[1]);
      else if(p[0]=="PARTIAL")detail="线索搜索达到时间或目录限制，结果不完整。";
     }
     if(!completed){incomplete=true;failure=detail;}
    }
    }
    scanSucceeded=!incomplete;empty.Text=incomplete?"扫描未完成\n请重试或以管理员模式运行":"没有检测到占用进程";
    status.Text=incomplete?"扫描未完成："+(failure.Length>0?failure:"请重试。"):(table.Rows.Count==0?"未检测到占用进程。":"检测到 "+table.Rows.Count+" 个占用进程。")+(denied>0?" 部分进程无访问权限。":"");
   }catch(Exception ex){if(!closing)status.Text="扫描失败："+ex.Message;}finally{helper=null;Busy(false);}
  }
  void AddResult(string[] fields) {
   string pid=fields[1],path=HandleScanner.Decode(fields[4]);long start=long.Parse(fields[2]);
   foreach(DataGridViewRow row in table.Rows)if(Convert.ToString(row.Cells[1].Value)==pid&&(long)row.Tag==start) {
    var paths=new List<string>(row.Cells[2].ToolTipText.Split('\n'));
    if(!paths.Contains(path)){paths.Add(path);row.Cells[2].ToolTipText=string.Join("\n",paths.ToArray());row.Cells[2].Value=paths[0]+"（共 "+paths.Count+" 项）";}return;
   }
   int index=table.Rows.Add(HandleScanner.Decode(fields[3]),pid,path);table.Rows[index].Tag=start;table.Rows[index].Cells[2].ToolTipText=path;
  }
  void StopClicked(object sender,DataGridViewCellEventArgs e) {
   if(busy||e.RowIndex<0||e.ColumnIndex!=3)return;var row=table.Rows[e.RowIndex];int pid=int.Parse(Convert.ToString(row.Cells[1].Value));
   string clue="";
   if(MessageBox.Show(this,clue+"结束 "+row.Cells[0].Value+"（PID "+pid+"）？\n该程序的未保存内容可能丢失。建议先正常关闭程序。","确认结束进程",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
   try{ProcessActions.Terminate(pid,(long)row.Tag);status.Text="已结束进程，请重新扫描或安全弹出。";for(int i=table.Rows.Count-1;i>=0;i--)if(Convert.ToString(table.Rows[i].Cells[1].Value)==pid.ToString())table.Rows.RemoveAt(i);}catch(Exception ex){status.Text="无法结束："+ex.Message;}
  }
  async void Eject() {
   var disk=disks.SelectedItem as ExternalDisk;if(busy||disk==null)return;
   var occupants=new List<Occupant>();
   if(table.Rows.Count>0){await ScanCore();if(closing||!scanSucceeded)return;if(disks.SelectedItem!=disk)return;
    foreach(DataGridViewRow row in table.Rows)occupants.Add(new Occupant {Pid=int.Parse(Convert.ToString(row.Cells[1].Value)),Started=(long)row.Tag,Name=Convert.ToString(row.Cells[0].Value)});
    if(occupants.Count>0){var names=new List<string>();foreach(var p in occupants)names.Add(p.Name+"（"+p.Pid+"）");if(MessageBox.Show(this,"将结束以下占用进程并弹出设备：\n\n"+string.Join("\n",names.ToArray())+"\n\n未保存的内容可能丢失。","强制弹出",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;}
   }
   if(busy||disks.SelectedItem!=disk)return;
   Busy(true);status.Text=occupants.Count>0?"正在释放占用并弹出…":"正在安全弹出…";
   try{string result=await Task.Factory.StartNew(delegate{if(occupants.Count>0){bool present=false;foreach(var item in Devices.Enumerate())if(item.InstanceId==disk.InstanceId&&item.Serial==disk.Serial)present=true;if(!present)throw new InvalidOperationException("设备已断开，请重新扫描。");}return EjectWorkflow.ReleaseAndEject(disk,occupants,delegate(Occupant p){ProcessActions.Terminate(p.Pid,p.Started);},Devices.Eject);});if(closing)return;if(result.StartsWith("安全弹出成功")){disks.Items.Remove(disk);table.Rows.Clear();empty.Text="设备已弹出";}else if(occupants.Count>0){table.Rows.Clear();empty.Text="占用已释放\n可重新扫描或尝试安全弹出";}status.Text=result;}catch(Exception ex){if(!closing)status.Text="弹出失败："+ex.Message;}finally{Busy(false);}
  }
 }
}







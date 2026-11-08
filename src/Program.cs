using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Drawing;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SafeDetach {
 static class Program {
  [STAThread] static int Main(string[] args) {
   Environment.CurrentDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   if(args.Length==2&&args[0]=="--apple-service")return AppleServiceScanner.Run(HandleScanner.Decode(args[1]));
   if(args.Length==3 && args[0]=="--handle-name")return HandleScanner.QuerySingle(int.Parse(args[1]),long.Parse(args[2]));
   if(args.Length==2 && args[0]=="--portable") {try{string instance=HandleScanner.Decode(args[1]);var reference=PortableTargets.Reference(instance);foreach(var other in Devices.EnumeratePortable())if(other.InstanceId!=instance&&PortableTargets.Reference(other.InstanceId).Key==reference.Key)throw new InvalidOperationException("设备身份重复，无法区分移动设备。");HandleScanner.SelectedPortableIdentity=reference;return HandleScanner.Run(new[]{"WPD:"+reference.Key},true);}catch(Exception ex){Console.WriteLine("ERROR\t"+HandleScanner.Encode(ex.Message));return 1;}}
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
  readonly Panel npcapNotice=new Panel();readonly Label npcapTitle=new Label(),npcapDetail=new Label();readonly Button npcapDownload=new Button(),npcapRetry=new Button();TableLayoutPanel content;readonly Timer supportTimer=new Timer {Interval=1000};
  readonly UiScale ui;readonly Panel viewport=new Panel {Dock=DockStyle.Fill,AutoScroll=true};TableLayoutPanel shell;bool arrangingViewport;
  readonly DeviceScanCache scanCache=new DeviceScanCache();readonly Timer autoScanTimer=new Timer {Interval=5000};bool scanning,actionInProgress,refreshingDevices,pendingSelectionScan,selectionScanQueued;
  readonly Func<ExternalDisk,ExternalDisk> refreshScanTarget;
  readonly bool autoScan;AppleConnectionMonitor appleMonitor=new AppleConnectionMonitor();readonly object workerLock=new object();readonly List<Process> workers=new List<Process>();volatile bool closing;bool deviceChangePending;readonly Timer deviceTimer=new Timer {Interval=800};
  public MainWindow():this(true) {}
  public MainWindow(bool loadDevices):this(loadDevices,UiScale.SystemDpi()) {}
  public MainWindow(bool loadDevices,int dpi):this(loadDevices,dpi,Devices.RefreshTarget,loadDevices) {}
  internal MainWindow(bool loadDevices,int dpi,Func<ExternalDisk,ExternalDisk> verifyTarget,bool automaticSelection) {
   SuspendLayout();ui=new UiScale(dpi);
   autoScan=automaticSelection;refreshScanTarget=verifyTarget;
   AutoScaleMode=AutoScaleMode.None;Text="SafeDetach 1.4.4";ClientSize=new Size(1104,681);StartPosition=FormStartPosition.CenterScreen;
   Font=new Font("Microsoft YaHei UI",10); BackColor=Color.White; ForeColor=Color.FromArgb(30,41,59);
   shell=new TableLayoutPanel {ColumnCount=2,RowCount=1,Margin=Padding.Empty};shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,250));shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
   var sidebar=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(18,24,18,18),ColumnCount=1,RowCount=5,BackColor=Color.FromArgb(245,247,250),Margin=Padding.Empty};
   foreach(float height in new float[]{88,30})sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,height));sidebar.RowStyles.Add(new RowStyle(SizeType.Percent,100));sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,44));sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,50));
   sidebar.Controls.Add(new Label {Name="brandName",Text="Safe\nDetach",Font=new Font(Font.FontFamily,18,FontStyle.Bold),ForeColor=Color.FromArgb(14,116,99),Dock=DockStyle.Fill},0,0);
   sidebar.Controls.Add(new Label {Text="外接设备",ForeColor=Color.FromArgb(100,116,139),Dock=DockStyle.Fill},0,1);
   disks.Dock=DockStyle.Fill;sidebar.Controls.Add(disks,0,2);
   disks.SelectedIndexChanged+=delegate {if(refreshingDevices)return;ShowSelectedDevice();if(autoScan){pendingSelectionScan=DeviceScanCache.Key(disks.SelectedItem as ExternalDisk)!=scanCache.ActiveKey;QueueSelectedScan();}};
   StyleButton(elevate,"管理员模式",false,delegate {try {Process.Start(new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas",WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows)});Close();}catch(Exception ex){status.Text=ex.Message;}});elevate.Dock=DockStyle.Fill;sidebar.Controls.Add(elevate,0,3);
   elevate.Visible=!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
   StyleButton(refresh,"刷新设备",false,delegate {RefreshDevices();});refresh.Dock=DockStyle.Fill;sidebar.Controls.Add(refresh,0,4);
   content=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(28,26,28,20),RowCount=5,ColumnCount=1,Margin=Padding.Empty};content.RowStyles.Add(new RowStyle(SizeType.Absolute,86));content.RowStyles.Add(new RowStyle(SizeType.Absolute,0));content.RowStyles.Add(new RowStyle(SizeType.Absolute,52));content.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.RowStyles.Add(new RowStyle(SizeType.Absolute,82));
   var heading=new TableLayoutPanel {Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,Margin=Padding.Empty};heading.RowStyles.Add(new RowStyle(SizeType.Absolute,42));heading.RowStyles.Add(new RowStyle(SizeType.Percent,100));deviceTitle.Text="选择设备";deviceTitle.Font=new Font(Font.FontFamily,20,FontStyle.Bold);deviceTitle.Dock=DockStyle.Fill;deviceTitle.AutoEllipsis=true;deviceDetail.Dock=DockStyle.Fill;deviceDetail.ForeColor=Color.FromArgb(100,116,139);deviceDetail.Text="从左侧选择要管理的设备";heading.Controls.Add(deviceTitle,0,0);heading.Controls.Add(deviceDetail,0,1);content.Controls.Add(heading,0,0);
   npcapNotice.Name="npcapNotice";npcapNotice.Dock=DockStyle.Fill;npcapNotice.Margin=new Padding(0,0,0,10);npcapNotice.Padding=new Padding(12,8,12,8);npcapNotice.BackColor=Color.FromArgb(240,247,255);npcapNotice.Visible=false;
   var supportLayout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};supportLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));supportLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,142));supportLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
   var supportText=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Margin=Padding.Empty};supportText.RowStyles.Add(new RowStyle(SizeType.Absolute,24));supportText.RowStyles.Add(new RowStyle(SizeType.Percent,100));npcapTitle.Dock=DockStyle.Fill;npcapTitle.Font=new Font(Font,FontStyle.Bold);npcapTitle.Margin=Padding.Empty;npcapDetail.Dock=DockStyle.Fill;npcapDetail.Font=new Font(Font.FontFamily,9);npcapDetail.ForeColor=Color.FromArgb(71,85,105);npcapDetail.Margin=Padding.Empty;supportText.Controls.Add(npcapTitle,0,0);supportText.Controls.Add(npcapDetail,0,1);supportLayout.Controls.Add(supportText,0,0);
   var supportActions=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Margin=new Padding(8,0,0,0)};supportActions.RowStyles.Add(new RowStyle(SizeType.Percent,50));supportActions.RowStyles.Add(new RowStyle(SizeType.Percent,50));StyleButton(npcapDownload,"前往官网下载",false,delegate {try{NpcapSupport.OpenDownloadPage();}catch(Exception ex){status.Text="无法打开浏览器："+ex.Message;}});StyleButton(npcapRetry,"安装后重试",false,delegate {RetryNpcap();});npcapDownload.Name="npcapDownload";npcapRetry.Name="npcapRetry";npcapDownload.Dock=npcapRetry.Dock=DockStyle.Fill;npcapDownload.Margin=npcapRetry.Margin=new Padding(0,1,0,1);npcapDownload.Font=npcapRetry.Font=new Font(Font.FontFamily,9);supportActions.Controls.Add(npcapDownload,0,0);supportActions.Controls.Add(npcapRetry,0,1);supportLayout.Controls.Add(supportActions,1,0);npcapNotice.Controls.Add(supportLayout);content.Controls.Add(npcapNotice,0,1);
   var tools=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};tools.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,124));processCount.Text="占用进程 · 0";processCount.Dock=DockStyle.Fill;processCount.TextAlign=ContentAlignment.MiddleLeft;processCount.Font=new Font(Font,FontStyle.Bold);tools.Controls.Add(processCount,0,0);StyleButton(scan,"扫描占用",false,delegate {Scan();});scan.Dock=DockStyle.Fill;tools.Controls.Add(scan,1,0);content.Controls.Add(tools,0,2);
   table.ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.DisableResizing;table.ColumnHeadersHeight=42;table.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.None;table.RowTemplate.Height=46;table.Dock=DockStyle.Fill;table.ReadOnly=true;table.AllowUserToAddRows=false;table.AllowUserToDeleteRows=false;table.RowHeadersVisible=false;table.BackgroundColor=Color.White;table.BorderStyle=BorderStyle.None;table.CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal;table.GridColor=Color.FromArgb(237,241,245);table.EnableHeadersVisualStyles=false;table.ColumnHeadersBorderStyle=DataGridViewHeaderBorderStyle.None;table.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(248,250,252);table.ColumnHeadersDefaultCellStyle.ForeColor=Color.FromArgb(100,116,139);table.ColumnHeadersDefaultCellStyle.Padding=new Padding(10,0,0,0);table.DefaultCellStyle.Padding=new Padding(10,0,0,0);table.DefaultCellStyle.SelectionBackColor=Color.FromArgb(233,245,241);table.DefaultCellStyle.SelectionForeColor=ForeColor;table.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;table.SelectionMode=DataGridViewSelectionMode.FullRowSelect;
   table.Columns.Add("name","程序 / 进程"); table.Columns.Add("pid","PID"); table.Columns.Add("path","占用内容");
   table.Columns[0].FillWeight=25; table.Columns[1].FillWeight=10; table.Columns[2].FillWeight=55;
   table.Columns.Add(new DataGridViewButtonColumn {Name="stop",HeaderText="",Text="结束进程",UseColumnTextForButtonValue=true,FlatStyle=FlatStyle.Flat,FillWeight=23});table.Columns[1].FillWeight=14;table.CellContentClick+=StopClicked;
   table.CellPainting+=delegate(object sender,DataGridViewCellPaintingEventArgs e){if(e.RowIndex>=0&&e.ColumnIndex==3){e.PaintBackground(e.ClipBounds,true);TextRenderer.DrawText(e.Graphics,"结束进程",Font,e.CellBounds,Color.FromArgb(170,65,47),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);e.Handled=true;}};
   var listHost=new Panel {Dock=DockStyle.Fill,Margin=Padding.Empty};listHost.Controls.Add(table);empty.Dock=DockStyle.Fill;empty.Text="尚未扫描\n选择设备后扫描占用";empty.TextAlign=ContentAlignment.MiddleCenter;empty.ForeColor=Color.FromArgb(148,163,184);empty.Font=new Font(Font.FontFamily,12);listHost.Controls.Add(empty);content.Controls.Add(listHost,0,3);
   var footer=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Padding=new Padding(0,18,0,0),Margin=Padding.Empty};footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,150));status.Dock=DockStyle.Fill;status.Margin=new Padding(0,4,16,0);status.Text="正在读取设备…";status.ForeColor=Color.FromArgb(100,116,139);footer.Controls.Add(status,0,0);StyleButton(eject,"安全弹出",true,delegate {Eject();});eject.Dock=DockStyle.Top;eject.Height=46;footer.Controls.Add(eject,1,0);content.Controls.Add(footer,0,4);
   shell.Controls.Add(sidebar,0,0);shell.Controls.Add(content,1,0);viewport.Controls.Add(shell);Controls.Add(viewport);table.RowsAdded+=delegate {UpdateResults();};table.RowsRemoved+=delegate {UpdateResults();};UpdateResults();Busy(false);
   deviceTimer.Tick+=delegate {if(!busy&&!actionInProgress&&deviceChangePending){deviceChangePending=false;deviceTimer.Stop();RefreshDevices();}};
   supportTimer.Tick+=delegate {UpdateNpcapNotice();};
   autoScanTimer.Tick+=delegate {AutomaticScanTick();};
   Shown+=delegate {if(loadDevices){UpdateNpcapNotice();supportTimer.Start();autoScanTimer.Start();appleMonitor.Start();RefreshDevices();}};FormClosing+=delegate {closing=true;deviceTimer.Stop();supportTimer.Stop();autoScanTimer.Stop();lock(workerLock)foreach(var worker in workers)try{if(!worker.HasExited)worker.Kill();}catch(InvalidOperationException){}};FormClosed+=delegate{deviceTimer.Dispose();supportTimer.Dispose();autoScanTimer.Dispose();appleMonitor.Dispose();};
   ui.Apply(this);disks.ConfigureDpi(ui.Dpi);table.ColumnHeadersHeight=ui.Px(42);table.RowTemplate.Height=ui.Px(46);table.ColumnHeadersDefaultCellStyle.Font=table.DefaultCellStyle.Font=table.Font;table.ColumnHeadersDefaultCellStyle.Padding=table.DefaultCellStyle.Padding=ui.Padding(new Padding(10,0,0,0));
   int[] minimumWidths={110,76,180,110};float[] weights={25,14,55,23};for(int i=0;i<table.Columns.Count;i++)table.Columns[i].MinimumWidth=ui.Px(minimumWidths[i]);for(int i=0;i<table.Columns.Count;i++)table.Columns[i].FillWeight=weights[i];
   status.ScrollBars=ScrollBars.Vertical;viewport.AutoScrollMinSize=ui.Size(920,480);viewport.SizeChanged+=delegate{ArrangeViewport();};ResumeLayout(true);ArrangeViewport();
  }
  void ArrangeViewport(){if(arrangingViewport||shell==null)return;arrangingViewport=true;try{var minimum=ui.Size(920,480);int width=viewport.Width,height=viewport.Height;bool horizontal=width<minimum.Width,vertical=height<minimum.Height;for(int i=0;i<2;i++){horizontal=width-(vertical?SystemInformation.VerticalScrollBarWidth:0)<minimum.Width;vertical=height-(horizontal?SystemInformation.HorizontalScrollBarHeight:0)<minimum.Height;}viewport.SuspendLayout();viewport.AutoScroll=false;viewport.AutoScrollPosition=Point.Empty;shell.Location=Point.Empty;viewport.AutoScrollMinSize=horizontal||vertical?minimum:Size.Empty;shell.Size=new Size(Math.Max(minimum.Width,width-(vertical?SystemInformation.VerticalScrollBarWidth:0)),Math.Max(minimum.Height,height-(horizontal?SystemInformation.HorizontalScrollBarHeight:0)));viewport.AutoScroll=true;viewport.ResumeLayout(true);shell.PerformLayout();}finally{arrangingViewport=false;}}
  void FitToWorkArea(Rectangle area){var minimum=SizeFromClientSize(ui.Size(920,480));MinimumSize=UiScale.Fit(minimum,area.Size);Size=UiScale.Fit(SizeFromClientSize(ui.Size(1104,681)),area.Size);if(StartPosition!=FormStartPosition.Manual&&(Left<area.Left||Right>area.Right||Top<area.Top||Bottom>area.Bottom))Location=new Point(area.Left+(area.Width-Width)/2,area.Top+(area.Height-Height)/2);ArrangeViewport();}
  protected override void OnLoad(EventArgs e){FitToWorkArea(Screen.FromControl(this).WorkingArea);base.OnLoad(e);}
  protected override void WndProc(ref Message message) {base.WndProc(ref message);if(message.Msg==0x219&&!closing){appleMonitor.InvalidateDevices();int change=message.WParam.ToInt32();if(change==7||change==0x8000||change==0x8004){scanCache.Clear();ShowSelectedDevice();}deviceChangePending=true;deviceTimer.Start();}}
  void StyleButton(Button button,string text,bool primary,EventHandler handler) {button.Text=text;button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderSize=primary?0:1;button.FlatAppearance.BorderColor=Color.FromArgb(220,227,234);button.BackColor=primary?Color.FromArgb(14,116,99):Color.White;button.ForeColor=primary?Color.White:ForeColor;button.Cursor=Cursors.Hand;button.Height=40;button.Margin=new Padding(0,4,0,4);button.Click+=handler;}
  void UpdateResults() {bool occupied=table.Rows.Count>0;eject.Text=occupied?"强制弹出":"安全弹出";eject.BackColor=occupied?Color.FromArgb(185,83,42):Color.FromArgb(14,116,99);processCount.Text="占用进程 · "+table.Rows.Count;empty.Visible=!occupied;}
  void Busy(bool value) {busy=value;if(closing)return;bool idle=!value&&!actionInProgress;refresh.Enabled=elevate.Enabled=npcapRetry.Enabled=idle;disks.Enabled=!actionInProgress&&(!value||scanning);scan.Enabled=eject.Enabled=idle&&disks.SelectedItem!=null;UpdateResults();}
  void ShowSelectedDevice(){if(closing)return;var selected=disks.SelectedItem as ExternalDisk;deviceTitle.Text=selected==null?"选择设备":DeviceList.Title(selected);deviceDetail.Text=selected==null?"从左侧选择要管理的设备":DeviceList.Detail(selected);string key=DeviceScanCache.Key(selected);var snapshot=scanCache.Get(key);RenderSnapshot(snapshot);if(scanning&&key!=scanCache.ActiveKey)status.Text+=" 等待上一设备扫描结束…";Busy(busy);}
  void RenderSnapshot(DeviceScanSnapshot snapshot){table.SuspendLayout();try{table.Rows.Clear();scanSucceeded=snapshot!=null&&snapshot.Completed;if(snapshot!=null){foreach(var fields in snapshot.Rows)AddResult(fields);empty.Text=snapshot.EmptyText;status.Text=snapshot.Status+"（结果时间 "+snapshot.Updated.ToLocalTime().ToString("HH:mm:ss")+"）";}else {empty.Text="尚未扫描\n等待扫描当前设备";status.Text=disks.SelectedItem==null?"请连接外接设备。":"等待扫描。";}}finally{table.ResumeLayout();UpdateResults();}}
  void QueueSelectedScan(){if(selectionScanQueued||!pendingSelectionScan||busy||actionInProgress||closing||deviceChangePending||!IsHandleCreated)return;selectionScanQueued=true;BeginInvoke((Action)delegate {selectionScanQueued=false;if(!pendingSelectionScan||busy||actionInProgress||closing||deviceChangePending)return;pendingSelectionScan=false;Scan();});}
  void AutomaticScanTick(){if(closing||busy||actionInProgress||deviceChangePending||refreshingDevices||selectionScanQueued||disks.SelectedItem==null)return;pendingSelectionScan=false;Scan();}
  void SetNpcapNotice(bool show,bool installed) {
   npcapTitle.Text=installed?"Apple 连接监听需要检查":"启用 Apple 连接识别";
   npcapDetail.Text=installed?"请检查 Npcap 安装或尝试管理员模式，然后点击重试。":"安装 Npcap 后可识别爱思等应用的设备连接。\n磁盘和 WPD 扫描仍可使用。";
   npcapRetry.Text=installed?"重新启用识别":"安装后重试";
   float height=show?ui.Px(96):0;if(content.RowStyles[1].Height!=height||npcapNotice.Visible!=show){content.SuspendLayout();content.RowStyles[1].Height=height;npcapNotice.Visible=show;content.ResumeLayout(true);}
  }
  void UpdateNpcapNotice(){if(closing)return;bool installed=NpcapSupport.IsInstalled;SetNpcapNotice(!installed||appleMonitor.CaptureUnavailable,installed);}
  async void RetryNpcap() {
   if(busy||actionInProgress||closing)return;
   if(!NpcapSupport.IsInstalled){SetNpcapNotice(true,false);status.Text="请从 Npcap 官网下载安装，完成后点击“安装后重试”。";return;}
   Busy(true);status.Text="正在启用 Apple 连接识别…";var previous=appleMonitor;var replacement=new AppleConnectionMonitor();appleMonitor=replacement;bool success=false;
   try {await Task.Factory.StartNew(delegate {previous.Dispose();replacement.Start();replacement.WaitForInitialization(4000);});if(closing)return;UpdateNpcapNotice();string failure=replacement.Status;success=failure==null;status.Text=success?"Apple 连接识别已启用，请重新连接应用后扫描。":failure;}
   catch(Exception ex){if(!closing)status.Text="启用失败："+ex.Message;}finally{Busy(false);}
   if(success&&!closing&&disks.SelectedItem!=null)await ScanCore();
  }
  async void RefreshDevices() {
   if(busy||actionInProgress)return;Busy(true);string selectedKey=DeviceScanCache.Key(disks.SelectedItem as ExternalDisk);
   try {var items=await Task.Factory.StartNew(delegate {return Devices.Enumerate();});if(closing)return;scanCache.Prune(items);refreshingDevices=true;try{disks.Items.Clear();foreach(var disk in items)disks.Items.Add(disk);if(items.Count>0){disks.SelectedIndex=0;foreach(var disk in items)if(DeviceScanCache.Key(disk)==selectedKey)disks.SelectedItem=disk;}}finally{refreshingDevices=false;}ShowSelectedDevice();if(items.Count==0)status.Text="未发现 USB 存储或移动设备。";}catch(Exception ex){if(!closing)status.Text="读取设备失败："+ex.Message;}finally{Busy(false);}if(autoScan&&!closing&&disks.SelectedItem!=null){pendingSelectionScan=true;QueueSelectedScan();}
  }
  async void Scan() {
   await ScanCore();
  }
  void RegisterWorker(Process process){lock(workerLock){if(closing){try{process.Kill();}catch(InvalidOperationException){}}else workers.Add(process);}}
  void UnregisterWorker(Process process){lock(workerLock)workers.Remove(process);}
  bool SelectedKey(string key){return DeviceScanCache.Key(disks.SelectedItem as ExternalDisk)==key;}
  void DrainResults(ConcurrentQueue<string> queue,ConcurrentDictionary<string,byte> internalProcesses,DeviceScanCache.Ticket ticket,List<string[]> rows,bool hadSnapshot){string line;bool added=false;while(queue.TryDequeue(out line)){if(closing||!scanCache.IsCurrent(ticket))continue;var fields=line.Split('\t');if(fields.Length==5&&(fields[0]=="H"||fields[0]=="M")&&!internalProcesses.ContainsKey(fields[1]+":"+fields[2])){rows.Add(fields);added=true;}}if(added&&!hadSnapshot){var preview=new DeviceScanSnapshot(rows,false,"正在扫描…","正在扫描…");if(scanCache.Preview(ticket,preview)&&SelectedKey(ticket.Key))RenderSnapshot(preview);}}
  async Task ScanCore() {
   var disk=disks.SelectedItem as ExternalDisk;if(busy||disk==null||closing)return;
   if(!disk.IsPortable&&disk.Drives.Count==0){status.Text="设备没有盘符。";return;}
   string key=DeviceScanCache.Key(disk);DeviceScanCache.Ticket ticket;if(!scanCache.TryBegin(key,out ticket))return;
   bool hadSnapshot=scanCache.Get(key)!=null;pendingSelectionScan=false;scanning=true;scanSucceeded=false;Busy(true);if(!hadSnapshot){var initial=new DeviceScanSnapshot(new string[0][],false,"正在扫描…","正在扫描…");scanCache.Preview(ticket,initial);RenderSnapshot(initial);}else status.Text="正在更新扫描，暂显示上次结果…";
   try {
    var verified=await Task.Factory.StartNew(delegate {return refreshScanTarget(disk);});
    if(closing)return;
    if(verified==null||DeviceScanCache.Key(verified)!=key){scanCache.Remove(key);if(SelectedKey(key)){RenderSnapshot(null);status.Text="设备已断开或身份变化，请刷新设备。";}return;}disk=verified;
    if(!disk.IsPortable&&disk.Drives.Count==0){var noDrive=new DeviceScanSnapshot(new string[0][],false,"设备没有盘符，无法扫描。","设备没有盘符");if(scanCache.Finish(ticket,noDrive)&&SelectedKey(key))RenderSnapshot(scanCache.Get(key));return;}
    if(!scanCache.IsCurrent(ticket))return;
    var rows=new List<string[]>();var queue=new ConcurrentQueue<string>();var phases=new List<Task<ScanPhaseResult>>();var internalProcesses=new ConcurrentDictionary<string,byte>();Action<Process> register=delegate(Process worker){internalProcesses.TryAdd(worker.Id+":"+worker.StartTime.ToUniversalTime().Ticks,0);RegisterWorker(worker);};string note="";
    if(disk.IsPortable){string instance=disk.InstanceId;var monitor=appleMonitor;phases.Add(Task.Factory.StartNew(delegate {var lines=monitor.Scan(instance);foreach(var line in lines)queue.Enqueue(line);return ScanPhaseResult.FromLines("Apple 连接",lines);}));}
    foreach(string mode in disk.IsPortable?new[]{"--portable"}:new[]{"--scan","--mapped"}) {string phase=mode=="--scan"?"文件句柄":mode=="--mapped"?"内存映射":"WPD 连接";string arguments=mode+" "+(disk.IsPortable?HandleScanner.Encode(disk.InstanceId):string.Join(" ",disk.Drives.ToArray()));phases.Add(ScanWorker.RunAsync(Application.ExecutablePath,arguments,phase,25000,queue.Enqueue,register,UnregisterWorker));}
    using(var progress=new Timer {Interval=100}) {
     progress.Tick+=delegate {DrainResults(queue,internalProcesses,ticket,rows,hadSnapshot);if(!closing&&scanCache.IsCurrent(ticket)&&SelectedKey(key)){int done=0;foreach(var phase in phases)if(phase.IsCompleted)done++;status.Text="正在扫描（"+done+"/"+phases.Count+"）"+(hadSnapshot?"，暂显示上次结果…":"，已发现 "+table.Rows.Count+" 个进程…");}};progress.Start();
     ScanPhaseResult[] results;try{results=await Task.WhenAll(phases);}finally{progress.Stop();}
     if(closing)return;DrainResults(queue,internalProcesses,ticket,rows,hadSnapshot);rows.RemoveAll(delegate(string[] fields){return internalProcesses.ContainsKey(fields[1]+":"+fields[2]);});var failures=new List<string>();var completed=new List<string>();int denied=0;
     foreach(var result in results){denied=Math.Max(denied,result.Denied);if(result.Note.Length>0)note=result.Note;if(result.Completed)completed.Add(result.Name);else failures.Add(result.Failure);}
     var processes=new HashSet<string>();foreach(var row in rows)processes.Add(row[1]+":"+row[2]);bool success=failures.Count==0;
     string message=(success?(processes.Count==0?"未检测到占用进程。":"检测到 "+processes.Count+" 个占用进程。"):"本轮扫描部分未完成。")+(failures.Count>0?(completed.Count>0?string.Join("、",completed.ToArray())+"已完成；":"")+string.Join("；",failures.ToArray()):"")+(denied>0?" 部分进程无访问权限。":"")+(processes.Count==0&&success?note:"");
     var snapshot=new DeviceScanSnapshot(rows,success,message,success?"没有检测到占用进程":"部分检查未完成\n请查看下方具体原因");if(scanCache.Finish(ticket,snapshot)&&SelectedKey(key))RenderSnapshot(scanCache.Get(key));
    }
   }catch(Exception ex){if(!closing){var failure=new DeviceScanSnapshot(new string[0][],false,"扫描失败："+ex.Message,"扫描失败，等待重试");if(scanCache.Finish(ticket,failure)&&SelectedKey(key))RenderSnapshot(scanCache.Get(key));}}
   finally{scanCache.Finish(ticket,new DeviceScanSnapshot(new string[0][],false,"扫描已取消。","等待重新扫描"));scanning=false;Busy(false);QueueSelectedScan();}
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
   if(busy||actionInProgress||e.RowIndex<0||e.ColumnIndex!=3)return;var row=table.Rows[e.RowIndex];int pid=int.Parse(Convert.ToString(row.Cells[1].Value));long started=(long)row.Tag;
   actionInProgress=true;Busy(busy);
   try {if(MessageBox.Show(this,"结束 "+row.Cells[0].Value+"（PID "+pid+"）？\n该程序的未保存内容可能丢失。建议先正常关闭程序。","确认结束进程",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
    try{ProcessActions.Terminate(pid,started);scanCache.RemoveProcess(pid,started);ShowSelectedDevice();status.Text="已结束进程，请重新扫描或安全弹出。";}catch(Exception ex){status.Text="无法结束："+ex.Message;}
   }finally{actionInProgress=false;Busy(busy);QueueSelectedScan();}
  }
  async void Eject() {
   var disk=disks.SelectedItem as ExternalDisk;if(busy||actionInProgress||disk==null)return;string key=DeviceScanCache.Key(disk);int generation=scanCache.Generation;actionInProgress=true;Busy(busy);
   try {
    var occupants=new List<Occupant>();
    if(table.Rows.Count>0){await ScanCore();if(closing||!scanSucceeded||!SelectedKey(key))return;
     foreach(DataGridViewRow row in table.Rows)occupants.Add(new Occupant {Pid=int.Parse(Convert.ToString(row.Cells[1].Value)),Started=(long)row.Tag,Name=Convert.ToString(row.Cells[0].Value)});
     if(occupants.Count>0){var names=new List<string>();foreach(var p in occupants)names.Add(p.Name+"（"+p.Pid+"）");if(MessageBox.Show(this,"将结束以下占用进程并弹出设备：\n\n"+string.Join("\n",names.ToArray())+"\n\n未保存的内容可能丢失。","强制弹出",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;}
    }
    if(busy||!SelectedKey(key))return;if(scanCache.Generation!=generation){status.Text="设备状态已变化，请重新扫描。";return;}Busy(true);status.Text=occupants.Count>0?"正在释放占用并弹出…":"正在安全弹出…";var terminated=new List<Occupant>();
    try {string result=await Task.Factory.StartNew(delegate{if(scanCache.Generation!=generation||(occupants.Count>0&&Devices.RefreshTarget(disk)==null))throw new InvalidOperationException("设备已断开或变化，请重新扫描。");return EjectWorkflow.ReleaseAndEject(disk,occupants,delegate(Occupant p){if(scanCache.Generation!=generation)throw new InvalidOperationException("设备状态已变化，请重新扫描。");ProcessActions.Terminate(p.Pid,p.Started);terminated.Add(p);},delegate(ExternalDisk target){if(scanCache.Generation!=generation)throw new InvalidOperationException("设备状态已变化，请重新扫描。");return Devices.Eject(target);});});if(closing)return;foreach(var process in terminated)scanCache.RemoveProcess(process.Pid,process.Started);
     if(result.StartsWith("安全弹出成功")){scanCache.Remove(key);disks.Items.Remove(disk);}else ShowSelectedDevice();status.Text=DeviceList.Title(disk)+"："+result;
    }catch(Exception ex){if(!closing){foreach(var process in terminated)scanCache.RemoveProcess(process.Pid,process.Started);ShowSelectedDevice();status.Text="弹出失败："+ex.Message;}}finally{Busy(false);}
   }finally{actionInProgress=false;Busy(busy);QueueSelectedScan();}
  }

 }
}

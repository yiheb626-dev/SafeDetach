using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using SafeDetach;

class DpiLayout {
 static readonly BindingFlags Flags=BindingFlags.Instance|BindingFlags.NonPublic;
 static T Field<T>(MainWindow form,string name){return (T)typeof(MainWindow).GetField(name,Flags).GetValue(form);}
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static void ButtonFits(Button button){if(!button.Visible)return;Size text=TextRenderer.MeasureText(button.Text,button.Font,Size.Empty,TextFormatFlags.SingleLine|TextFormatFlags.NoPadding);Check(button.ClientSize.Width>=text.Width+4&&button.ClientSize.Height>=text.Height+4,"Button text clipped: "+button.Text);Check(button.Parent.ClientRectangle.Contains(button.Bounds),"Button outside parent: "+button.Text);}
 static void Buttons(Control root){foreach(Control child in root.Controls){var button=child as Button;if(button!=null)ButtonFits(button);Buttons(child);}}
 static void Validate(MainWindow form,UiScale ui,bool notice){
  form.PerformLayout();Application.DoEvents();var table=Field<DataGridView>(form,"table");var list=Field<DeviceList>(form,"disks");
  Check(table.ColumnHeadersHeight==ui.Px(42)&&table.RowTemplate.Height==ui.Px(46),"Grid heights not scaled");Check(table.Rows[0].Height>=table.Font.Height+ui.Px(12),"Grid row font clipped");
  foreach(DataGridViewColumn column in table.Columns){if(column.HeaderText.Length==0)continue;var text=TextRenderer.MeasureText(column.HeaderText,table.ColumnHeadersDefaultCellStyle.Font);Check(column.Width>=text.Width+table.ColumnHeadersDefaultCellStyle.Padding.Horizontal,"Grid heading clipped: "+column.HeaderText);}
  Check(list.ItemHeight>=ui.Px(78)&&list.ItemHeight>=list.Font.Height*2+ui.Px(24),"Owner-drawn device rows not scaled");
  var title=Field<Label>(form,"deviceTitle");Check(title.Height>=title.Font.Height,"Device heading clipped");var brand=(Label)form.Controls.Find("brandName",true)[0];Check(brand.Height>=brand.Font.Height*2,"Brand text clipped");
  var panel=Field<Panel>(form,"npcapNotice");Check(panel.Visible==notice,"Notice visibility mismatch");
  if(notice){var bounds=panel.RectangleToScreen(panel.ClientRectangle);foreach(string name in new[]{"npcapDownload","npcapRetry"}){var button=Field<Button>(form,name);Check(bounds.Contains(button.RectangleToScreen(button.ClientRectangle)),"Support actions clipped");}}
  Buttons(form);
 }
 static void Save(MainWindow form,string directory,int dpi,string state){if(directory==null)return;using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(Point.Empty,form.Size));image.Save(Path.Combine(directory,"dpi-"+dpi+"-"+state+".png"));}}
 static void Run(int dpi,string directory){var ui=new UiScale(dpi);using(var form=new MainWindow(false,dpi)){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-30000,-30000);form.Show();form.Location=new Point(-30000,-30000);
  var list=Field<DeviceList>(form,"disks");var disk=new ExternalDisk {Name="Lexar ES3",InstanceId="fixture"};disk.Drives.Add("H:");list.Items.Add(disk);list.Items.Add(new ExternalDisk {Name="Apple iPad",IsPortable=true});list.SelectedIndex=0;
  typeof(MainWindow).GetMethod("AddResult",Flags).Invoke(form,new object[]{new[]{"H","123456","100",HandleScanner.Encode("i4Tools"),HandleScanner.Encode("Apple 设备连接")}});
  var notice=typeof(MainWindow).GetMethod("SetNpcapNotice",Flags);var fit=typeof(MainWindow).GetMethod("FitToWorkArea",Flags);fit.Invoke(form,new object[]{new Rectangle(0,0,1920,1040)});form.Location=new Point(-30000,-30000);Check(form.Width<=1920&&form.Height<=1040,"Window exceeds working area");
  notice.Invoke(form,new object[]{false,true});Validate(form,ui,false);Save(form,directory,dpi,"normal");
  notice.Invoke(form,new object[]{true,false});Validate(form,ui,true);Save(form,directory,dpi,"notice");
  float row=Field<TableLayoutPanel>(form,"content").RowStyles[1].Height;for(int i=0;i<10;i++){notice.Invoke(form,new object[]{false,true});notice.Invoke(form,new object[]{true,false});}Check(Field<TableLayoutPanel>(form,"content").RowStyles[1].Height==row,"Repeated notice progressively scales layout");
  form.Size=form.MinimumSize;Validate(form,ui,true);var viewport=Field<Panel>(form,"viewport");if(viewport.Width>=ui.Px(920)&&viewport.Height>=ui.Px(480))Check(!viewport.HorizontalScroll.Visible&&!viewport.VerticalScroll.Visible,"False scrollbars at minimum window");
  fit.Invoke(form,new object[]{new Rectangle(0,0,1366,728)});form.Location=new Point(-30000,-30000);Validate(form,ui,true);Check(form.Width<=1366&&form.Height<=728,"Small-screen window exceeds work area");
  if(ui.Px(920)>viewport.Width||ui.Px(480)>viewport.Height){Check(viewport.HorizontalScroll.Visible||viewport.VerticalScroll.Visible,"Small screen cannot reach overflow controls");viewport.ScrollControlIntoView(Field<Button>(form,"eject"));Application.DoEvents();var visible=viewport.RectangleToScreen(viewport.ClientRectangle);var eject=Field<Button>(form,"eject");Check(visible.Contains(eject.RectangleToScreen(eject.ClientRectangle)),"Eject button unreachable by scrolling");viewport.AutoScrollPosition=Point.Empty;}
  if(dpi==192)Save(form,directory,dpi,"small-screen");form.Close();
 }Console.WriteLine("PASS: "+(dpi*100/96)+"% fonts, grid, owner drawing, notice, minimum sizing and small-screen overflow");}
 [STAThread] static int Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);try{Console.WriteLine("Native process DPI: "+UiScale.SystemDpi());string directory=args.Length==1?args[0]:null;if(directory!=null)Directory.CreateDirectory(directory);foreach(int dpi in new[]{96,120,144,168,192,240})Run(dpi,directory);return 0;}catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex.Message);return 1;}}
}

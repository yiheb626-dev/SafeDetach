using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
namespace SafeDetach {
 public sealed class DeviceList:ListBox {
  UiScale ui=new UiScale(96);
  public DeviceList(){DrawMode=DrawMode.OwnerDrawFixed;BorderStyle=BorderStyle.None;BackColor=Color.FromArgb(245,247,250);IntegralHeight=false;ItemHeight=78;}
  public static string Title(ExternalDisk disk){return (disk.Name??"外接设备").Replace(" SCSI Disk Device","").Replace(" USB Device","");}
  public static string Detail(ExternalDisk disk){return disk.IsPortable?"移动设备 · USB":"外接存储 · "+(disk.Drives.Count==0?"无盘符":string.Join(" / ",disk.Drives.ToArray()));}
  public void ConfigureDpi(int dpi){ui=new UiScale(dpi);ItemHeight=Math.Max(ui.Px(78),Font.Height*2+ui.Px(24));Invalidate();}
  protected override void OnFontChanged(EventArgs e){base.OnFontChanged(e);if(ui!=null)ItemHeight=Math.Max(ui.Px(78),Font.Height*2+ui.Px(24));}
  protected override void OnDrawItem(DrawItemEventArgs e){
   if(e.Index<0||e.Index>=Items.Count)return;var disk=Items[e.Index] as ExternalDisk;if(disk==null)return;
   bool selected=(e.State&DrawItemState.Selected)!=0;using(var background=new SolidBrush(BackColor))e.Graphics.FillRectangle(background,e.Bounds);
   var bounds=new Rectangle(e.Bounds.X,e.Bounds.Y+ui.Px(3),e.Bounds.Width-ui.Px(2),e.Bounds.Height-ui.Px(6));
   using(var fill=new SolidBrush(selected?Color.FromArgb(224,240,233):BackColor))e.Graphics.FillRectangle(fill,bounds);
   e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
   using(var pen=new Pen(selected?Color.FromArgb(14,116,99):Color.FromArgb(100,116,139),1.6f*ui.Factor)){
    int x=bounds.X+ui.Px(13),y=bounds.Y+(bounds.Height-ui.Px(26))/2;
    if(disk.IsPortable){e.Graphics.DrawRectangle(pen,x+ui.Px(3),y,ui.Px(17),ui.Px(27));e.Graphics.DrawLine(pen,x+ui.Px(9),y+ui.Px(23),x+ui.Px(14),y+ui.Px(23));}else{e.Graphics.DrawRectangle(pen,x,y+ui.Px(3),ui.Px(25),ui.Px(22));e.Graphics.DrawLine(pen,x+ui.Px(4),y+ui.Px(18),x+ui.Px(21),y+ui.Px(18));e.Graphics.DrawEllipse(pen,x+ui.Px(18),y+ui.Px(21),ui.Px(2),ui.Px(2));}
   }
   using(var font=new Font(Font,FontStyle.Bold))TextRenderer.DrawText(e.Graphics,Title(disk),font,new Rectangle(bounds.X+ui.Px(49),bounds.Y+ui.Px(12),Math.Max(1,bounds.Width-ui.Px(57)),Font.Height+ui.Px(5)),Color.FromArgb(30,41,59),TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix|TextFormatFlags.SingleLine);
   using(var font=ui.Font(9,FontStyle.Regular))TextRenderer.DrawText(e.Graphics,Detail(disk),font,new Rectangle(bounds.X+ui.Px(49),bounds.Y+Font.Height+ui.Px(19),Math.Max(1,bounds.Width-ui.Px(57)),font.Height+ui.Px(4)),Color.FromArgb(100,116,139),TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix|TextFormatFlags.SingleLine);
   if((e.State&DrawItemState.Focus)!=0)e.DrawFocusRectangle();
  }
 }
}

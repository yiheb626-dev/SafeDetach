using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
namespace SafeDetach {
 public sealed class DeviceList:ListBox {
  public DeviceList(){DrawMode=DrawMode.OwnerDrawFixed;BorderStyle=BorderStyle.None;BackColor=Color.FromArgb(245,247,250);IntegralHeight=false;ItemHeight=78;}
  public static string Title(ExternalDisk disk){return (disk.Name??"外接设备").Replace(" SCSI Disk Device","").Replace(" USB Device","");}
  public static string Detail(ExternalDisk disk){return disk.IsPortable?"手机 · USB":"外接存储 · "+(disk.Drives.Count==0?"无盘符":string.Join(" / ",disk.Drives.ToArray()));}
  protected override void OnFontChanged(EventArgs e){base.OnFontChanged(e);ItemHeight=Math.Max(70,Font.Height*4);}
  protected override void OnDrawItem(DrawItemEventArgs e){
   if(e.Index<0||e.Index>=Items.Count)return;var disk=Items[e.Index] as ExternalDisk;if(disk==null)return;
   bool selected=(e.State&DrawItemState.Selected)!=0;using(var background=new SolidBrush(BackColor))e.Graphics.FillRectangle(background,e.Bounds);
   var bounds=new Rectangle(e.Bounds.X,e.Bounds.Y+3,e.Bounds.Width-2,e.Bounds.Height-6);
   using(var fill=new SolidBrush(selected?Color.FromArgb(224,240,233):BackColor))e.Graphics.FillRectangle(fill,bounds);
   e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
   using(var pen=new Pen(selected?Color.FromArgb(14,116,99):Color.FromArgb(100,116,139),1.6f)){
    int x=bounds.X+13,y=bounds.Y+(bounds.Height-26)/2;
    if(disk.IsPortable){e.Graphics.DrawRectangle(pen,x+3,y,17,27);e.Graphics.DrawLine(pen,x+9,y+23,x+14,y+23);}else{e.Graphics.DrawRectangle(pen,x,y+3,25,22);e.Graphics.DrawLine(pen,x+4,y+18,x+21,y+18);e.Graphics.DrawEllipse(pen,x+18,y+21,2,2);}
   }
   using(var font=new Font(Font,FontStyle.Bold))TextRenderer.DrawText(e.Graphics,Title(disk),font,new Rectangle(bounds.X+49,bounds.Y+12,bounds.Width-57,Font.Height+5),Color.FromArgb(30,41,59),TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix);
   using(var font=new Font(Font.FontFamily,Math.Max(8,Font.Size-1)))TextRenderer.DrawText(e.Graphics,Detail(disk),font,new Rectangle(bounds.X+49,bounds.Y+Font.Height+19,bounds.Width-57,Font.Height+4),Color.FromArgb(100,116,139),TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix);
   if((e.State&DrawItemState.Focus)!=0)e.DrawFocusRectangle();
  }
 }
}

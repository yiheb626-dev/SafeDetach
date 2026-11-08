using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace SafeDetach {
 // Geometry and fonts use one DPI value; WinForms must not scale them a second time.
 public sealed class UiScale {
  public readonly int Dpi;public float Factor {get{return Dpi/96f;}}
  public UiScale(int dpi){Dpi=Math.Max(96,Math.Min(768,dpi));}
  public static int SystemDpi(){using(var graphics=Graphics.FromHwnd(IntPtr.Zero))return (int)Math.Round(graphics.DpiY);}
  public int Px(float value){return (int)Math.Round(value*Factor,MidpointRounding.AwayFromZero);}
  public Size Size(int width,int height){return new Size(Px(width),Px(height));}
  public Padding Padding(Padding value){return new Padding(Px(value.Left),Px(value.Top),Px(value.Right),Px(value.Bottom));}
  public Font Font(float points,FontStyle style){return new Font("Microsoft YaHei UI",points*Dpi/72f,style,GraphicsUnit.Pixel);}
  sealed class Record {public Control Control;public Padding Padding,Margin;public float Points;public FontStyle Style;public readonly List<float> Rows=new List<float>(),Columns=new List<float>();}
  static void Collect(Control control,List<Record> records){control.SuspendLayout();var item=new Record {Control=control,Padding=control.Padding,Margin=control.Margin,Points=control.Font.SizeInPoints,Style=control.Font.Style};var table=control as TableLayoutPanel;if(table!=null){foreach(RowStyle row in table.RowStyles)item.Rows.Add(row.Height);foreach(ColumnStyle column in table.ColumnStyles)item.Columns.Add(column.Width);}records.Add(item);foreach(Control child in control.Controls)Collect(child,records);}
  public void Apply(Control root){var records=new List<Record>();Collect(root,records);root.Scale(new SizeF(Factor,Factor));foreach(var item in records){item.Control.Padding=Padding(item.Padding);item.Control.Margin=Padding(item.Margin);item.Control.Font=Font(item.Points,item.Style);var table=item.Control as TableLayoutPanel;if(table!=null){for(int i=0;i<item.Rows.Count;i++)if(table.RowStyles[i].SizeType==SizeType.Absolute)table.RowStyles[i].Height=Px(item.Rows[i]);for(int i=0;i<item.Columns.Count;i++)if(table.ColumnStyles[i].SizeType==SizeType.Absolute)table.ColumnStyles[i].Width=Px(item.Columns[i]);}}
   for(int i=records.Count-1;i>=0;i--)records[i].Control.ResumeLayout(false);
  }
  public static Size Fit(Size preferred,Size available){return new Size(Math.Min(preferred.Width,available.Width),Math.Min(preferred.Height,available.Height));}
 }
}

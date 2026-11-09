using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace SafeDetach {
 public sealed class ScanSpinner:Control {
  readonly Timer animation=new Timer {Interval=60};bool running,disposing;float angle;
  public ScanSpinner(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.SupportsTransparentBackColor,true);BackColor=Color.Transparent;ForeColor=Color.FromArgb(14,116,99);Size=new Size(18,18);TabStop=false;Visible=false;AccessibleName="正在扫描";animation.Tick+=delegate {angle=(angle+24)%360;Invalidate();};}
  public bool Running {get{return running;}set{if(running==value)return;running=value;Visible=value;if(!value)angle=0;UpdateAnimation();Invalidate();}}
  void UpdateAnimation(){if(!disposing)animation.Enabled=running&&Visible&&!IsDisposed;}
  protected override void OnVisibleChanged(EventArgs e){base.OnVisibleChanged(e);if(animation!=null)UpdateAnimation();}
  protected override void OnPaint(PaintEventArgs e){base.OnPaint(e);if(!running)return;e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;float diameter=Math.Min(ClientSize.Width,ClientSize.Height),stroke=Math.Max(1.5f,diameter/9);var bounds=new RectangleF((ClientSize.Width-diameter)/2+stroke,(ClientSize.Height-diameter)/2+stroke,diameter-stroke*2,diameter-stroke*2);if(bounds.Width<=0)return;using(var track=new Pen(Color.FromArgb(224,235,231),stroke))e.Graphics.DrawEllipse(track,bounds);using(var arc=new Pen(ForeColor,stroke)){arc.StartCap=arc.EndCap=LineCap.Round;e.Graphics.DrawArc(arc,bounds,angle,105);}}
  protected override void Dispose(bool disposing){if(disposing&&!this.disposing){this.disposing=true;animation.Stop();animation.Dispose();}base.Dispose(disposing);}
 }
}

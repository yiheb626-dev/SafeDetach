using System;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Windows.Forms;
using SafeDetach;
class Recognition {
 [STAThread] static int Main(string[] args) {
  if(args.Length>0&&args[0]=="fixture") {
   using(var mapped=MemoryMappedFile.CreateFromFile(args[1],FileMode.Open))
   using(var view=mapped.CreateViewAccessor())
   using(var form=new Form {Text=Path.GetFileName(args[1]),WindowState=FormWindowState.Minimized,ShowInTaskbar=false}) {
    form.Shown+=delegate {Console.WriteLine("READY");Console.Out.Flush();};Application.Run(form);
   }return 0;
  }
  string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"SafeDetach-识别-"+Guid.NewGuid().ToString("N")+".jpg");Process holder=null;
  try {
   File.WriteAllBytes(path,new byte[4096]);
   holder=Process.Start(new ProcessStartInfo(typeof(Recognition).Assembly.Location,"fixture \""+path+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true});
   var ready=holder.StandardOutput.ReadLineAsync();if(!ready.Wait(10000)||ready.Result!="READY")throw new Exception("Fixture startup failed");
   foreach(string mode in new[]{"--mapped","--windows"}) {
    string argument=mode=="--mapped"?Path.GetPathRoot(path).TrimEnd('\\'):Path.GetDirectoryName(path);
    using(var scanner=Process.Start(new ProcessStartInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"SafeDetach.exe"),mode+" \""+argument+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})) {
     var output=scanner.StandardOutput.ReadToEndAsync();if(!scanner.WaitForExit(30000)){scanner.Kill();throw new Exception("Scan timeout");}
     bool found=false;foreach(string line in output.Result.Split('\n')) {string[] p=line.Trim().Split('\t');if(p.Length==5&&p[1]==holder.Id.ToString()&&HandleScanner.Decode(p[4])==path&&p[0]==(mode=="--mapped"?"M":"W"))found=true;}
     if(!found)throw new Exception(mode+" missing fixture: "+output.Result);Console.WriteLine("PASS: "+mode+" real fixture detected");
    }
   }
   if(WindowClueScanner.IsFileTitle("ordinary window")||WindowClueScanner.IsFileTitle("..\\photo.jpg")||!WindowClueScanner.IsFileTitle("照片.JPG"))throw new Exception("Title classification failed");
   Console.WriteLine("PASS: window title guards");
   int portable=0;foreach(var device in Devices.Enumerate()) {if(device.IsPortable){portable++;Console.WriteLine("PORTABLE: "+device.Name);} }
   Console.WriteLine("PASS: portable enumeration; observed "+portable);return 0;
  }catch(Exception ex){Console.WriteLine("FAIL: "+ex);return 1;}
  finally{if(holder!=null){if(!holder.HasExited)holder.Kill();holder.WaitForExit();holder.Dispose();}if(File.Exists(path))File.Delete(path);}
 }
}

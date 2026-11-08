using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SafeDetach {
 public sealed class ScanPhaseResult {
  public string Name,Detail="",Note="";public bool Completed,TimedOut;public int Denied;public long ElapsedMs;
  bool done,failed;
  public void Observe(string line){try{var fields=line.Split('\t');if(fields[0]=="DONE"&&fields.Length>=3){Denied=Math.Max(Denied,int.Parse(fields[2]));done=true;}else if(fields[0]=="ERROR"&&fields.Length>=2){Detail=HandleScanner.Decode(fields[1]);failed=true;}else if(fields[0]=="NOTE"&&fields.Length>=2)Note=HandleScanner.Decode(fields[1]);else if(fields[0]=="PARTIAL"){Detail="已达到查询限制。";failed=true;}}catch(FormatException){Detail="扫描返回内容无效。";failed=true;}}
  public void Finish(bool exited,int exitCode,long elapsed){ElapsedMs=elapsed;TimedOut=!exited;Completed=exited&&exitCode==0&&done&&!failed;if(TimedOut)Detail="超过时间限制";else if(!Completed&&Detail.Length==0)Detail=exitCode!=0?"扫描进程异常退出":"扫描未返回完整结果";}
  public string Failure {get{return Name+(TimedOut?"超时": "未完成")+"："+Detail;}}
  public static ScanPhaseResult FromLines(string name,string[] lines){var result=new ScanPhaseResult {Name=name};foreach(var line in lines)result.Observe(line);result.Finish(true,0,0);return result;}
 }
 public static class ScanWorker {
  public static Task<ScanPhaseResult> RunAsync(string executable,string arguments,string name,int timeout,Action<string> output,Action<Process> register,Action<Process> unregister) {
   return Task.Factory.StartNew(delegate {
    var result=new ScanPhaseResult {Name=name};var clock=Stopwatch.StartNew();
    using(var process=new Process {StartInfo=new ProcessStartInfo(executable,arguments){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true,WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.Windows)}}) {
     bool started=false;
     try {process.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data!=null){result.Observe(e.Data);if(output!=null)output(e.Data);}};
      process.Start();started=true;if(register!=null)register(process);process.BeginOutputReadLine();bool exited=process.WaitForExit(timeout);
      if(!exited){try{process.Kill();}catch(InvalidOperationException){}process.WaitForExit(3000);}
      if(process.HasExited)process.WaitForExit();result.Finish(exited,process.HasExited?process.ExitCode:-1,clock.ElapsedMilliseconds);
     }catch(Exception ex){result.Detail=ex.Message;result.Completed=false;try{if(started&&!process.HasExited)process.Kill();}catch(InvalidOperationException){} }
     finally{if(started&&unregister!=null)unregister(process);}
    }
    return result;
   });
  }
 }
}

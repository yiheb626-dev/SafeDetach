using System;
using System.Collections.Generic;
namespace SafeDetach {
 public sealed class Occupant {public int Pid;public long Started;public string Name;}
 public static class EjectWorkflow {
  public static string ReleaseAndEject(ExternalDisk disk,IEnumerable<Occupant> occupants,Action<Occupant> terminate,Func<ExternalDisk,string> eject) {
   var targets=new List<Occupant>(occupants);foreach(var occupant in targets)if(occupant.Pid<=4||occupant.Started<=0)throw new InvalidOperationException("无法确认占用进程身份，请重新扫描。");
   var handled=new HashSet<string>();
   foreach(var occupant in targets){if(handled.Add(occupant.Pid+"|"+occupant.Started)){try{terminate(occupant);}catch(Exception ex){throw new InvalidOperationException("无法结束 "+occupant.Name+"（"+occupant.Pid+"）："+ex.Message);}}}
   return eject(disk);
  }
 }
}

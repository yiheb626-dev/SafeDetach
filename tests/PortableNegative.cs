using System;
using SafeDetach;
class PortableNegative {
 [STAThread] static int Main(string[] args) {
  if(args.Length==3&&args[0]=="--handle-name")return HandleScanner.QuerySingle(int.Parse(args[1]),long.Parse(args[2]));
  var reference=PortableTargets.Reference(HandleScanner.Decode(args[0]));reference.Serial="wrong-device-"+Guid.NewGuid().ToString("N");
  HandleScanner.SelectedPortableIdentity=reference;return HandleScanner.Run(new[]{"WPD:"+reference.Key},true);
 }
}

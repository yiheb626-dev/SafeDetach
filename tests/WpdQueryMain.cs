using SafeDetach;
class WpdQueryMain {
 static int Main(string[] args){if(args.Length==3&&args[0]=="--handle-name")return HandleScanner.QuerySingle(int.Parse(args[1]),long.Parse(args[2]));HandleScanner.DiagnosticUnnamedFile=delegate(System.IntPtr handle){try{var type=PortableProtocol.DeviceType(handle);var identity=PortableProtocol.Read(handle);return "WPD_IDENTITY_OK type="+type.ToString("X8")+" model="+identity.Model+" hasSerial="+(!string.IsNullOrEmpty(identity.Serial));}catch(System.Exception ex){return "WPD_ERROR "+ex.Message;}};return HandleScanner.Run(new[]{""},true,int.Parse(args[0]));}
}

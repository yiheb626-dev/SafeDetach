using SafeDetach;
class NativeProbe {
 static int Main(string[] args) {if(args.Length==3&&args[0]=="--handle-name")return HandleScanner.QuerySingle(int.Parse(args[1]),long.Parse(args[2]));return HandleScanner.Run(new[]{""},true,int.Parse(args[0]));}
}


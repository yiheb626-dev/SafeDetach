using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SafeDetach {
 public sealed class PortableIdentity {
  public string Serial,Manufacturer,Model;
  static string Part(string value){return Convert.ToBase64String(Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant()));}
  public string Key {get{return Part(Manufacturer)+"|"+Part(Model)+"|"+Part(Serial);}}
 }
 public static class PortableProtocol {
  [StructLayout(LayoutKind.Sequential)] struct Key {public Guid Format;public uint Id;public Key(Guid format,uint id){Format=format;Id=id;}}
  [StructLayout(LayoutKind.Sequential)] struct Overlapped {public IntPtr Internal,InternalHigh;public uint Offset,OffsetHigh;public IntPtr Event;}
  [ComImport,Guid("B32F4002-BB27-45FF-AF4F-06631C1E8DAD"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface Serializer {
   void Decode([In,MarshalAs(UnmanagedType.LPArray,SizeParamIndex=1)] byte[] buffer,uint length,out IntPtr values);
  }
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetValue(IntPtr self,ref Key key,IntPtr variant);
  [DllImport("ole32.dll")] static extern int PropVariantClear(IntPtr value);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(IntPtr handle,uint code,IntPtr input,int inputSize,IntPtr output,int outputSize,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetOverlappedResult(IntPtr handle,IntPtr overlapped,out uint returned,bool wait);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CancelIoEx(IntPtr handle,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateEvent(IntPtr security,bool manual,bool initial,string name);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("ntdll.dll")] static extern int NtQueryVolumeInformationFile(IntPtr handle,IntPtr status,IntPtr info,uint length,int kind);
  static readonly Guid Common=new Guid("F0422A9C-5DC8-4440-B5BD-5DF28835658A"),Properties=new Guid("9E5582E4-0814-44E6-981A-B2998D583804"),Device=new Guid("26D4979A-E643-4626-9E2B-736DC0C92FDC");
  public static int DeviceType(IntPtr handle) {
   IntPtr status=Marshal.AllocHGlobal(IntPtr.Size*2),info=Marshal.AllocHGlobal(8);
   try {int code=NtQueryVolumeInformationFile(handle,status,info,8,4);return code==0?Marshal.ReadInt32(info):code;}finally{Marshal.FreeHGlobal(info);Marshal.FreeHGlobal(status);}
  }
  static byte[] Request() {
   using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)) {
    writer.Write(13u);writer.Write(new Guid("0C15D503-D017-47CE-9016-7B3F978721CC").ToByteArray());writer.Write(3u);
    writer.Write(Common.ToByteArray());writer.Write(1001u);writer.Write(72u);writer.Write(Properties.ToByteArray());
    writer.Write(Common.ToByteArray());writer.Write(1002u);writer.Write(19u);writer.Write(6u);
    byte[] root=Encoding.Unicode.GetBytes("DEVICE\0");writer.Write(Properties.ToByteArray());writer.Write(1001u);writer.Write(31u);writer.Write((uint)root.Length);writer.Write(root);return stream.ToArray();
   }
  }
  sealed class Variant:IDisposable {
   public IntPtr Pointer;
   public Variant(IntPtr values,Key key) {
    Pointer=Marshal.AllocHGlobal(24);for(int i=0;i<24;i++)Marshal.WriteByte(Pointer,i,0);
    var get=(GetValue)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(values),6*IntPtr.Size),typeof(GetValue));
    int result=get(values,ref key,Pointer);if(result<0){Dispose();Marshal.ThrowExceptionForHR(result);}
   }
   public int Type {get{return (ushort)Marshal.ReadInt16(Pointer);}}
   public IntPtr Data {get{return Marshal.ReadIntPtr(Pointer,8);}}
   public void Dispose(){if(Pointer!=IntPtr.Zero){PropVariantClear(Pointer);Marshal.FreeHGlobal(Pointer);Pointer=IntPtr.Zero;}}
  }
  static string StringValue(IntPtr values,uint id) {using(var v=new Variant(values,new Key(Device,id))){if(v.Type!=31)throw new InvalidDataException("设备身份格式错误。");return Marshal.PtrToStringUni(v.Data)??"";}}
  public static PortableIdentity Parse(byte[] response) {
   object serializer=null;IntPtr values=IntPtr.Zero;
   try {
    serializer=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("0B91A74B-AD7C-4A9D-B563-29EEF9167172")));
    ((Serializer)serializer).Decode(response,(uint)response.Length,out values);
    using(var hr=new Variant(values,new Key(Common,1003))){if(hr.Type!=10)throw new InvalidDataException("设备查询状态格式错误。");Marshal.ThrowExceptionForHR(Marshal.ReadInt32(hr.Pointer,8));}
    using(var nested=new Variant(values,new Key(Properties,1004))){if(nested.Type!=13)throw new InvalidDataException("设备查询响应格式错误。");var identity=new PortableIdentity {Serial=StringValue(nested.Data,9),Manufacturer=StringValue(nested.Data,7),Model=StringValue(nested.Data,8)};if(string.IsNullOrWhiteSpace(identity.Serial))throw new InvalidDataException("设备未提供唯一序列号。");return identity;}
   }finally {if(values!=IntPtr.Zero)Marshal.Release(values);if(serializer!=null)Marshal.FinalReleaseComObject(serializer);}
  }
  // Call only inside the disposable scan worker. The event's low bit suppresses
  // completion packets on the original application's completion port.
  public static PortableIdentity Read(IntPtr handle) {
   byte[] request=Request();IntPtr input=Marshal.AllocHGlobal(request.Length),output=Marshal.AllocHGlobal(65536),overlapped=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Overlapped))),signal=IntPtr.Zero;
   try {
    Marshal.Copy(request,0,input,request.Length);signal=CreateEvent(IntPtr.Zero,true,false,null);if(signal==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    Marshal.StructureToPtr(new Overlapped {Event=new IntPtr(signal.ToInt64()|1)},overlapped,false);
    uint bytes;bool immediate=DeviceIoControl(handle,0x00404108,input,request.Length,output,65536,out bytes,overlapped);
    if(!immediate&&Marshal.GetLastWin32Error()!=997)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    if(!immediate&&WaitForSingleObject(signal,1500)!=0){CancelIoEx(handle,overlapped);WaitForSingleObject(signal,uint.MaxValue);throw new TimeoutException("设备查询超时。");}
    if(!GetOverlappedResult(handle,overlapped,out bytes,false))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    if(bytes==0||bytes>65536)throw new InvalidDataException("设备响应大小错误。");byte[] response=new byte[bytes];Marshal.Copy(output,response,0,(int)bytes);return Parse(response);
   }finally{if(signal!=IntPtr.Zero)CloseHandle(signal);Marshal.FreeHGlobal(overlapped);Marshal.FreeHGlobal(output);Marshal.FreeHGlobal(input);}
  }
 }
}

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
class WpdReadProbe {
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(IntPtr handle,uint code,byte[] input,int inputLength,byte[] output,int outputLength,out int returned,IntPtr overlapped);
 public static string Read(IntPtr handle) {
  byte[] request;
  Guid common=new Guid("F0422A9C-5DC8-4440-B5BD-5DF28835658A"),properties=new Guid("9E5582E4-0814-44E6-981A-B2998D583804");
  using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)) {
   writer.Write(13u);writer.Write(new Guid("0C15D503-D017-47CE-9016-7B3F978721CC").ToByteArray());writer.Write(3u);
   writer.Write(common.ToByteArray());writer.Write(1001u);writer.Write(72u);writer.Write(properties.ToByteArray());
   writer.Write(common.ToByteArray());writer.Write(1002u);writer.Write(19u);writer.Write(6u);
   byte[] root=Encoding.Unicode.GetBytes("DEVICE\0");writer.Write(properties.ToByteArray());writer.Write(1001u);writer.Write(31u);writer.Write((uint)root.Length);writer.Write(root);request=stream.ToArray();
  }
  byte[] response=new byte[65536];int bytes;
  if(!DeviceIoControl(handle,0x00404108,request,request.Length,response,response.Length,out bytes,IntPtr.Zero))return "WPD_QUERY_ERROR "+Marshal.GetLastWin32Error();
  return "WPD_REPLY "+bytes+" "+Convert.ToBase64String(response,0,bytes);
 }
}

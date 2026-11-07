using System;
using System.Runtime.InteropServices;
using System.Threading;
[StructLayout(LayoutKind.Sequential)] struct PropertyKey {public Guid Format;public uint Id;}
[ComImport,Guid("A1567595-4C2F-4574-A6FA-ECEF917B9A40"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface DeviceManager {
 void GetDevices(IntPtr devices,ref uint count);
}
[ComImport,Guid("625E2DF8-6392-4CF0-9AD1-3CFA5F17775C"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface PortableDevice {
 void Open([MarshalAs(UnmanagedType.LPWStr)]string id,[MarshalAs(UnmanagedType.Interface)]DeviceValues values);
 void SendCommand(uint flags,IntPtr parameters,out IntPtr results);
 void Content(out DeviceContent content);
 void Capabilities(out IntPtr capabilities);
 void Cancel();
 void Close();
}
[ComImport,Guid("6A96ED84-7C73-4480-9938-BF5AF477D426"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface DeviceContent {
 void EnumObjects(uint flags,[MarshalAs(UnmanagedType.LPWStr)]string parent,IntPtr filter,out ObjectIds ids);
}
[ComImport,Guid("10ECE955-CF41-4728-BFA0-41EEDF1BBF19"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface ObjectIds {
 void Next(uint count,out IntPtr objectId,ref uint fetched);
}
[ComImport,Guid("6848F6F2-3155-4F86-B6F5-263EEEAB3143"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface DeviceValues {
 void GetCount(out uint count);
 void GetAt(uint index,IntPtr key,IntPtr value);
 void SetValue(ref PropertyKey key,IntPtr value);
 void GetValue(ref PropertyKey key,IntPtr value);
 void SetStringValue(ref PropertyKey key,[MarshalAs(UnmanagedType.LPWStr)]string value);
 void GetStringValue(ref PropertyKey key,out IntPtr value);
 void SetUnsignedIntegerValue(ref PropertyKey key,uint value);
}
class PortableConnection {
 [STAThread] static int Main() {
  object manager=null,values=null,device=null;DeviceContent content=null;ObjectIds objects=null;IntPtr ids=IntPtr.Zero;uint count=0;
  try {
   manager=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("0AF10CEC-2ECD-4B92-9581-34F6AE0637F3")));
   ((DeviceManager)manager).GetDevices(IntPtr.Zero,ref count);if(count==0)throw new Exception("No portable devices");
   ids=Marshal.AllocCoTaskMem((int)count*IntPtr.Size);for(int i=0;i<count;i++)Marshal.WriteIntPtr(ids,i*IntPtr.Size,IntPtr.Zero);
   ((DeviceManager)manager).GetDevices(ids,ref count);string target=null;
   for(int i=0;i<count;i++){string id=Marshal.PtrToStringUni(Marshal.ReadIntPtr(ids,i*IntPtr.Size));if(id.IndexOf("vid_05ac",StringComparison.OrdinalIgnoreCase)>=0)target=id;}
   if(target==null)throw new Exception("No Apple WPD interface");
   values=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("0C15D503-D017-47CE-9016-7B3F978721CC")));
   var access=new PropertyKey {Format=new Guid("204D9F0C-2292-4080-9F42-40664E70F859"),Id=9};((DeviceValues)values).SetUnsignedIntegerValue(ref access,0x80000000);
   device=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("F7C0039A-4762-488A-B4B3-760EF9A1BA9B")));
   bool phased=Environment.GetEnvironmentVariable("SAFEDETACH_FIXTURE_PHASES")=="1";
   if(phased){Console.WriteLine("BEFORE "+System.Diagnostics.Process.GetCurrentProcess().Id);Console.Out.Flush();Console.ReadLine();}
   ((PortableDevice)device).Open(target,(DeviceValues)values);
   ((PortableDevice)device).Content(out content);
   content.EnumObjects(0,"DEVICE",IntPtr.Zero,out objects);
   uint fetched=0;IntPtr objectId;objects.Next(1,out objectId,ref fetched);if(objectId!=IntPtr.Zero)Marshal.FreeCoTaskMem(objectId);
   Console.WriteLine("READY "+System.Diagnostics.Process.GetCurrentProcess().Id);Console.Out.Flush();
   if(phased){Console.ReadLine();uint more=0;IntPtr next;objects.Next(1,out next,ref more);if(next!=IntPtr.Zero)Marshal.FreeCoTaskMem(next);Marshal.FinalReleaseComObject(objects);objects=null;Marshal.FinalReleaseComObject(content);content=null;((PortableDevice)device).Close();Console.WriteLine("CLOSED");Console.Out.Flush();Console.ReadLine();}
   else{int hold=30000;int requested;if(int.TryParse(Environment.GetEnvironmentVariable("SAFEDETACH_FIXTURE_HOLD_MS"),out requested))hold=Math.Max(100,Math.Min(30000,requested));Thread.Sleep(hold);}
   GC.KeepAlive(objects);GC.KeepAlive(content);GC.KeepAlive(device);return 0;
  }catch(Exception ex){Console.WriteLine(ex);return 1;}
  finally{if(objects!=null)Marshal.FinalReleaseComObject(objects);if(content!=null)Marshal.FinalReleaseComObject(content);if(device!=null)Marshal.FinalReleaseComObject(device);if(values!=null)Marshal.FinalReleaseComObject(values);if(manager!=null)Marshal.FinalReleaseComObject(manager);if(ids!=IntPtr.Zero){for(int i=0;i<count;i++){IntPtr id=Marshal.ReadIntPtr(ids,i*IntPtr.Size);if(id!=IntPtr.Zero)Marshal.FreeCoTaskMem(id);}Marshal.FreeCoTaskMem(ids);}}
 }
}


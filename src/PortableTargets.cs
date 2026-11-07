using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace SafeDetach {
 public static class PortableTargets {
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_Interface_List_SizeW(out uint length,ref Guid interfaceClass,string instance,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_Interface_ListW(ref Guid interfaceClass,string instance,char[] buffer,uint length,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public static PortableIdentity Reference(string instance) {
   Guid category=new Guid("6AC27878-A6FA-4155-BA85-F98F491D4F33");uint length;
   if(CM_Get_Device_Interface_List_SizeW(out length,ref category,instance,0)!=0||length<2)throw new InvalidOperationException("设备接口不可用，请解锁手机后重试。");
   var buffer=new char[length];if(CM_Get_Device_Interface_ListW(ref category,instance,buffer,length,0)!=0)throw new InvalidOperationException("设备已断开，请刷新。");
   foreach(string path in new string(buffer).Split('\0')) {
    if(path.Length==0)continue;IntPtr handle=CreateFile(path,0x80000000,3,IntPtr.Zero,3,0x40000000,IntPtr.Zero);
    if(handle==new IntPtr(-1))continue;
    try{return PortableProtocol.Read(handle);}finally{CloseHandle(handle);}
   }
   throw new InvalidOperationException("无法读取手机身份，请解锁手机后重试。");
  }
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Locate_DevNodeW(out uint node,string id,uint flags);
  [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Parent(out uint parent,uint node,uint flags);
  [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Child(out uint child,uint node,uint flags);
  [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Sibling(out uint sibling,uint node,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_IDW(uint node,StringBuilder name,int length,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_DevNode_Registry_PropertyW(uint node,uint property,out uint type,byte[] buffer,ref uint length,uint flags);
  public static string[] Resolve(string instance) {
   uint node;if(CM_Locate_DevNodeW(out node,instance,0)!=0)throw new InvalidOperationException("设备已断开。");
   // Group interfaces only up to this phone's physical USB node, never its hub.
   for(int depth=0;depth<12;depth++) {
    var id=new StringBuilder(1024);if(CM_Get_Device_IDW(node,id,id.Capacity,0)!=0)break;
    string value=id.ToString();if(value.StartsWith("USB\\",StringComparison.OrdinalIgnoreCase)&&value.IndexOf("&MI_",StringComparison.OrdinalIgnoreCase)<0)break;
    uint parent;if(CM_Get_Parent(out parent,node,0)!=0)break;
    var parentId=new StringBuilder(1024);CM_Get_Device_IDW(parent,parentId,parentId.Capacity,0);
    if(!parentId.ToString().StartsWith("USB\\VID_",StringComparison.OrdinalIgnoreCase))break;node=parent;
   }
   var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var queue=new Queue<uint>();queue.Enqueue(node);
   for(int count=0;queue.Count>0&&count<128;count++) {
    uint item=queue.Dequeue(),type,length=8192;var buffer=new byte[length];
    if(CM_Get_DevNode_Registry_PropertyW(item,15,out type,buffer,ref length,0)==0) {string name=Encoding.Unicode.GetString(buffer,0,(int)length).TrimEnd('\0');if(name.StartsWith("\\Device\\",StringComparison.OrdinalIgnoreCase))result.Add(name);}
    uint child;if(CM_Get_Child(out child,item,0)==0)do{queue.Enqueue(child);uint next;if(CM_Get_Sibling(out next,child,0)!=0)break;child=next;}while(true);
   }
   if(result.Count==0)throw new InvalidOperationException("无法读取设备接口，请以管理员身份重试。");
   var array=new string[result.Count];result.CopyTo(array);return array;
  }
 }
}

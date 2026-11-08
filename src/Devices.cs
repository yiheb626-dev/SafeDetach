using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace SafeDetach {
 public sealed class ExternalDisk {
  public string Name, InstanceId, Serial;
  public uint Number;
  public bool IsPortable;
  public List<string> Drives = new List<string>();
  public override string ToString() { return Name + "  [" + (IsPortable ? "移动设备 · 无盘符" : string.Join(" / ", Drives.ToArray())) + "]"; }
 }
 public static class Devices {
  public static List<ExternalDisk> Enumerate() {
   var result = new List<ExternalDisk>();
   using(var search = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
   using(var disks = search.Get()) foreach(ManagementObject disk in disks) using(disk) {
    string id = Convert.ToString(disk["PNPDeviceID"]);
    bool external = Convert.ToString(disk["InterfaceType"]) == "USB" || HasUsbAncestor(id);
    if(!external) continue;
    var item = new ExternalDisk { Name=Convert.ToString(disk["Model"]), InstanceId=id, Serial=Convert.ToString(disk["SerialNumber"]), Number=Convert.ToUInt32(disk["Index"]) };
    using(var partitions = disk.GetRelated("Win32_DiskPartition")) foreach(ManagementObject partition in partitions) using(partition)
    using(var volumes = partition.GetRelated("Win32_LogicalDisk")) foreach(ManagementObject volume in volumes) using(volume) item.Drives.Add(Convert.ToString(volume["DeviceID"]));
    result.Add(item);
   }
   using(var search = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE PNPClass='WPD' AND Present=TRUE"))
   using(var portable = search.Get()) foreach(ManagementObject device in portable) using(device) {
    string id=Convert.ToString(device["PNPDeviceID"]);
    // Disk volumes also expose WPD nodes. Only add actual USB portable interfaces.
    if(!id.StartsWith("USB\\",StringComparison.OrdinalIgnoreCase))continue;
    result.Add(new ExternalDisk {Name=Convert.ToString(device["Name"]),InstanceId=id,Serial="",IsPortable=true});
   }
   return result;
  }
  static bool HasUsbAncestor(string id) {
   uint node; if(CM_Locate_DevNodeW(out node,id,0)!=0) return false;
   for(int i=0;i<12;i++) {
    var name=new StringBuilder(1024);
    if(CM_Get_Device_IDW(node,name,name.Capacity,0)==0 && name.ToString().StartsWith("USB\\",StringComparison.OrdinalIgnoreCase)) return true;
    uint parent; if(CM_Get_Parent(out parent,node,0)!=0) break; node=parent;
   }
   return false;
  }
  public static string Eject(ExternalDisk disk) {
   // Re-resolve the saved physical identity; never act on a drive letter alone.
   uint node; uint status=CM_Locate_DevNodeW(out node,disk.InstanceId,0);
   if(status!=0) return "设备已断开或无法定位（"+status+"）。";
   uint target=node; bool removable=false;
   for(int i=0;i<12;i++) {
    uint state,problem;
    if(CM_Get_DevNode_Status(out state,out problem,node,0)==0 && (state & 0x4000)!=0) { target=node; removable=true; break; }
    var name=new StringBuilder(1024);CM_Get_Device_IDW(node,name,name.Capacity,0);
    // Never climb above the first physical USB device to a hub/controller.
    if(name.ToString().StartsWith("USB\\",StringComparison.OrdinalIgnoreCase)) break;
    uint parent; if(CM_Get_Parent(out parent,node,0)!=0) break; node=parent;
   }
   if(!removable)return "Windows 未将此设备标记为可安全移除。";
   // Reject a shared ancestor: removing a multi-LUN bridge may remove other disks.
   foreach(var other in Enumerate()) {
    if(other.InstanceId==disk.InstanceId)continue;
    uint sibling;if(CM_Locate_DevNodeW(out sibling,other.InstanceId,0)!=0)continue;
    for(int i=0;i<12;i++) {if(sibling==target)return "此设备与其他磁盘共用移除节点，请使用 Windows 安全删除硬件统一处理。";uint parent;if(CM_Get_Parent(out parent,sibling,0)!=0)break;sibling=parent;}
   }
   int veto; var reason=new StringBuilder(260);
   status=CM_Request_Device_EjectW(target,out veto,reason,reason.Capacity,0);
   return status==0 ? "安全弹出成功，可以拔下设备。" : "Windows 拒绝弹出："+VetoDescription(veto)+"（状态 "+status+" / 原因 "+veto+"）。"+(reason.Length>0?"占用者："+reason:"请重新扫描占用，或以管理员身份重试。");
  }
  public static string VetoDescription(int veto) {
   string[] labels={"未知原因","未知阻止原因","旧式设备阻止","设备仍有打开的句柄","应用程序阻止","服务阻止","尚未完成的关闭操作","设备阻止","驱动程序阻止","设备不支持此操作","电源不足","设备不允许停用","旧式驱动程序阻止","权限不足"};
   return veto>=0&&veto<labels.Length?labels[veto]:"系统阻止";
  }
  [DllImport("cfgmgr32.dll")] static extern uint CM_Get_DevNode_Status(out uint status,out uint problem,uint node,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Locate_DevNodeW(out uint node,string id,uint flags);
  [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Parent(out uint parent,uint node,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_IDW(uint node,StringBuilder buffer,int length,uint flags);
  [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Request_Device_EjectW(uint node,out int veto,StringBuilder name,int length,uint flags);
 }
}

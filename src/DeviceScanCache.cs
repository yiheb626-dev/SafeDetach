using System;
using System.Collections.Generic;
using System.Text;

namespace SafeDetach {
 public sealed class DeviceScanSnapshot {
  public readonly string[][] Rows;public readonly bool Completed;public readonly string Status,EmptyText;public readonly DateTime Updated;
  public DeviceScanSnapshot(IEnumerable<string[]> rows,bool completed,string status,string emptyText,DateTime? updated=null){var copy=new List<string[]>();foreach(var row in rows)copy.Add((string[])row.Clone());Rows=copy.ToArray();Completed=completed;Status=status;EmptyText=emptyText;Updated=updated??DateTime.UtcNow;}
 }
 // All access is on the UI thread. Workers only write to their own output queue.
 public sealed class DeviceScanCache {
  sealed class Entry {public DeviceScanSnapshot Visible,LastGood;}
  public sealed class Ticket {internal object Entry;public string Key;public long Sequence;}
  readonly Dictionary<string,Entry> entries=new Dictionary<string,Entry>();Ticket active;long sequence;volatile int generation;
  static string Part(string value){return Convert.ToBase64String(Encoding.UTF8.GetBytes((value??"").ToUpperInvariant()));}
  public static string Key(ExternalDisk disk){return disk==null?null:(disk.IsPortable?"P:":"D:")+Part(disk.InstanceId)+":"+Part(disk.Serial);}
  public string ActiveKey {get{return active==null?null:active.Key;}}
  public int Generation {get{return generation;}}
  public bool TryBegin(string key,out Ticket ticket){ticket=null;if(active!=null||key==null)return false;Entry entry;if(!entries.TryGetValue(key,out entry)){entry=new Entry();entries.Add(key,entry);}ticket=new Ticket {Entry=entry,Key=key,Sequence=++sequence};active=ticket;return true;}
  public bool IsCurrent(Ticket ticket){Entry entry;return ticket!=null&&object.ReferenceEquals(active,ticket)&&entries.TryGetValue(ticket.Key,out entry)&&object.ReferenceEquals(entry,ticket.Entry);}
  public DeviceScanSnapshot Get(string key){Entry entry;return key!=null&&entries.TryGetValue(key,out entry)?entry.Visible:null;}
  public bool Preview(Ticket ticket,DeviceScanSnapshot snapshot){if(!IsCurrent(ticket))return false;var entry=(Entry)ticket.Entry;if(entry.Visible==null||entry.LastGood==null)entry.Visible=snapshot;return true;}
  public bool Finish(Ticket ticket,DeviceScanSnapshot snapshot){bool current=IsCurrent(ticket);if(object.ReferenceEquals(active,ticket))active=null;if(!current)return false;var entry=(Entry)ticket.Entry;
   if(snapshot.Completed){entry.Visible=entry.LastGood=snapshot;}
   else if(entry.LastGood!=null)entry.Visible=new DeviceScanSnapshot(entry.LastGood.Rows,false,snapshot.Status+" 保留上次完整结果。",snapshot.EmptyText,entry.LastGood.Updated);
   else entry.Visible=snapshot;return true;
  }
  public void Remove(string key){if(key!=null&&entries.Remove(key))generation++;}
  public void Clear(){entries.Clear();generation++;}
  public void Prune(IEnumerable<ExternalDisk> devices){var keep=new HashSet<string>();foreach(var device in devices)keep.Add(Key(device));var remove=new List<string>();foreach(var key in entries.Keys)if(!keep.Contains(key))remove.Add(key);foreach(var key in remove)Remove(key);}
  public void RemoveProcess(int pid,long started){foreach(var entry in entries.Values){var rows=new List<string[]>();if(entry.Visible!=null){foreach(var row in entry.Visible.Rows)if(row[1]!=pid.ToString()||row[2]!=started.ToString())rows.Add(row);if(rows.Count!=entry.Visible.Rows.Length){entry.Visible=new DeviceScanSnapshot(rows,false,"已结束进程，等待重新扫描。","等待重新扫描");entry.LastGood=null;}}}}
 }
}

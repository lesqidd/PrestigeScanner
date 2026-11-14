#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$Mode)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    throw 'Open 64-bit Windows PowerShell 5.1 as administrator to run this scanner.'
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Start Windows PowerShell with Run as administrator.'
}
$outputFolder = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($outputFolder)) {
    $outputFolder = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($outputFolder)) { $outputFolder = $env:TEMP }
}

Write-Host 'Prestige Scanner' -ForegroundColor Cyan
Write-Host '[1] Live Java memory'
Write-Host '[2] Loader files, Prefetch and PowerShell history'
Write-Host '[3] Both scans'
if (!$Mode) { $Mode = Read-Host 'Select 1, 2 or 3' }
if ($Mode -notin '1','2','3') { throw 'Choose 1, 2 or 3.' }

$engine = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

public class PrestigePowerShellScanner {
    const string Jar = "c2a6f8fb26c88eb9fc823fc9dd8373f268cdacdc59b2b636ace353a9b0dc59f1";
    const string Exe = "d7508c0022d959e4566d2cc1742cc0b7752b6fd1e692ecab7cef7ac6b9d8eec3";
    const string Host = "api.prestigeclient.vip";
    const string OriginalExe = "icloudjsclownht2ogv.exe";
    const string OriginalJar = "lesqid is gay.jar";
    static readonly Encoding Bytes = Encoding.GetEncoding(28591);
    static readonly HashSet<string> Findings = new HashSet<string>();
    static StreamWriter report;
    static void Log(string s) { Console.WriteLine(s); report.WriteLine(s); }
    static void Hit(string s) { if (Findings.Add(s)) Log(s); }
    static string Sample(string hashes) {
        foreach (string item in hashes.Split(',',';')) {
            string h = item.Trim();
            if (h.StartsWith("SHA256=",StringComparison.OrdinalIgnoreCase)) h=h.Substring(7);
            if (h.Equals(Jar,StringComparison.OrdinalIgnoreCase)) return "JAR loader";
            if (h.Equals(Exe,StringComparison.OrdinalIgnoreCase)) return "EXE loader";
        }
        return null;
    }
    static bool Java(string path) { string n=Path.GetFileName(path).ToLowerInvariant(); return n=="java.exe" || n=="javaw.exe"; }
    static bool Original(string path) { string n=Path.GetFileName(path); return String.Equals(n,OriginalExe,StringComparison.OrdinalIgnoreCase)||String.Equals(n,OriginalJar,StringComparison.OrdinalIgnoreCase); }
    static bool LoaderStructure(string path) {
        using(var f=File.OpenRead(path)) using(var z=new ZipArchive(f,ZipArchiveMode.Read)) {
            var mf=z.GetEntry("META-INF/MANIFEST.MF");
            var cls=z.GetEntry("net/taskflow/sched/TaskScheduler.class");
            if(mf==null || mf.Length>65536 || cls==null || cls.Length<8) return false;
            using(var code=cls.Open()) {
                if(code.ReadByte()!=202 || code.ReadByte()!=254 || code.ReadByte()!=186 || code.ReadByte()!=190) return false;
            }
            using(var reader=new StreamReader(mf.Open())) {
                string manifest=reader.ReadToEnd().Replace("\r","");
                return manifest.Split('\n').Contains("Main-Class: net.taskflow.sched.TaskScheduler") &&
                    manifest.Split('\n').Contains("Implementation-Title: taskflow") &&
                    manifest.Split('\n').Contains("Implementation-Version: 2.5.15");
            }
        }
    }
    static void Disk(string[] roots) {
        int files=0, hashes=0, errors=0, links=0;
        var pending=new Stack<string>(roots);
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while(pending.Count>0 && files<250000) {
            string path=Path.GetFullPath(pending.Pop());
            if(!seen.Add(path)) continue;
            try {
                var attr=File.GetAttributes(path);
                if((attr & FileAttributes.ReparsePoint)!=0) {links++; continue;}
                if((attr & FileAttributes.Directory)!=0) {
                    foreach(string child in Directory.EnumerateFileSystemEntries(path)) pending.Push(child);
                    continue;
                }
                files++;
                long length=new FileInfo(path).Length;
                if(path.EndsWith(".jar",StringComparison.OrdinalIgnoreCase) && length<=4*1024*1024 && length>0) {
                    try { if(LoaderStructure(path)) Hit("REVIEW | JAR manifest and class match the reference loader structure | "+path); }
                    catch(InvalidDataException){errors++;}
                }
                if(length!=8119 && length!=237848) continue;
                hashes++;
                using(var f=File.OpenRead(path)) using(var sha=SHA256.Create()) {
                    string h=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
                    string sample=Sample(h);
                    if(sample!=null) Hit("EXACT | "+sample+" on disk | "+path+" | "+h);
                }
            } catch(UnauthorizedAccessException){errors++;} catch(IOException){errors++;}
        }
        Log("Disk coverage: "+files+" files inspected; "+hashes+" size candidates hashed; "+errors+" unavailable; "+links+" links skipped; scan limit reached: "+(pending.Count>0));
    }
    [StructLayout(LayoutKind.Sequential)] struct Region {
        public IntPtr Base, AllocationBase; public uint AllocationProtect; public UIntPtr Size; public uint State,Protect,Type;
    }
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr p,out Region r,UIntPtr size);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h,IntPtr p,byte[] data,UIntPtr size,out UIntPtr count);
    static readonly string[] Markers = {Host+"/stage2Download", Host+"/launcherDownload","net/taskflow/sched/TaskScheduler","net.taskflow.sched.TaskScheduler"};
    static readonly string[] ConsoleLines = {"Initializing Prestige","Hook mode: Legacy (JVMTI retransform)"};
    static bool ContainsText(string block,string marker) {
        return block.IndexOf(marker,StringComparison.Ordinal)>=0 ||
            block.IndexOf(Bytes.GetString(Encoding.Unicode.GetBytes(marker)),StringComparison.Ordinal)>=0;
    }
    static bool PrivateDll(IntPtr process, IntPtr allocation) {
        byte[] header=new byte[4096]; UIntPtr read;
        ReadProcessMemory(process,allocation,header,(UIntPtr)header.Length,out read);
        int n=(int)read.ToUInt64();
        if(n<64 || header[0]!='M' || header[1]!='Z') return false;
        int pe=BitConverter.ToInt32(header,60);
        if(pe<64 || pe>n-24 || BitConverter.ToUInt32(header,pe)!=0x4550) return false;
        int sections=BitConverter.ToUInt16(header,pe+6);
        int optional=BitConverter.ToUInt16(header,pe+20);
        if(sections<1 || sections>96 || optional<64 || pe+24+optional+sections*40>n) return false;
        int magic=BitConverter.ToUInt16(header,pe+24);
        if((magic!=267 && magic!=523) || (BitConverter.ToUInt16(header,pe+22)&0x2000)==0) return false;
        for(int i=0;i<sections;i++)
            if((BitConverter.ToUInt32(header,pe+24+optional+i*40+36)&0x20000000)!=0) return true;
        return false;
    }
    static void Memory() {
        var processes=Process.GetProcessesByName("java").Concat(Process.GetProcessesByName("javaw")).ToArray();
        Log("Live Java processes: "+processes.Length+" (includes non-Minecraft JVMs)");
        foreach(var p in processes) using(p) {
            int pid=p.Id;
            try { var start=p.StartTime.ToUniversalTime(); Log("Java PID "+pid+" | start UTC "+start.ToString("u")+" | uptime "+(DateTime.UtcNow-start).ToString(@"d\.hh\:mm\:ss")); }
            catch(System.ComponentModel.Win32Exception){Log("Start time unavailable for PID "+pid);}
            catch(InvalidOperationException){Log("PID "+pid+" exited.");continue;}
            IntPtr h=OpenProcess(0x410,false,pid);
            if(h==IntPtr.Zero){Log("Unavailable: JVM PID "+pid+" could not be opened.");continue;}
            long address=0,total=0; int failures=0;
            var matched=new HashSet<string>();
            var consoleMatches=new HashSet<string>();
            var inspectedAllocations=new HashSet<IntPtr>();
            var clock=Stopwatch.StartNew();
            long nextProgress=3;
            byte[] buf=new byte[512*1024];
            string tail="";
            try {
                Region r;
                while(clock.Elapsed.TotalSeconds<60 && VirtualQueryEx(h,new IntPtr(address),out r,(UIntPtr)Marshal.SizeOf(typeof(Region))).ToUInt64()>0) {
                    long end=checked(r.Base.ToInt64()+(long)r.Size.ToUInt64());
                    if(end<=address) break;
                    uint perm=r.Protect & 255;
                    if(r.State==0x1000 && r.Type==0x20000 && (r.Protect&256)==0 && perm>=16 &&
                        inspectedAllocations.Add(r.AllocationBase) && PrivateDll(h,r.AllocationBase))
                        Hit("GENERIC | Private allocation with executable protection and DLL headers | PID "+pid+" | allocation 0x"+r.AllocationBase.ToInt64().ToString("X")+" | possible manual map; payload identity unknown");
                    if(r.State==0x1000 && (r.Protect&256)==0 && (perm==2||perm==4||perm==8||perm==32||perm==64||perm==128)) {
                        for(long pos=address;pos<end && clock.Elapsed.TotalSeconds<60;) {
                            int size=(int)Math.Min(buf.Length,end-pos);
                            UIntPtr count;
                            ReadProcessMemory(h,new IntPtr(pos),buf,(UIntPtr)size,out count);
                            int n=(int)count.ToUInt64();
                            if(n>0) {
                                string block=tail+Bytes.GetString(buf,0,n);
                                if(consoleMatches.Count<ConsoleLines.Length) {
                                    foreach(string line in ConsoleLines)
                                        if(!consoleMatches.Contains(line) && ContainsText(block,line)) consoleMatches.Add(line);
                                    if(consoleMatches.Count==ConsoleLines.Length)
                                        Hit("REVIEW | Both reported Prestige Legacy console strings in Java PID "+pid+" | same-process text evidence; build and execution unverified");
                                }
                                foreach(string m in Markers) {
                                    if(matched.Contains(m)) continue;
                                    string wide=Bytes.GetString(Encoding.Unicode.GetBytes(m));
                                    if(block.IndexOf(m,StringComparison.Ordinal)>=0 || block.IndexOf(wide,StringComparison.Ordinal)>=0) {
                                        matched.Add(m); Hit("REVIEW | JVM PID "+pid+" contains loader marker | "+m+" | string presence alone does not establish execution");
                                    }
                                }
                                total+=n; tail=block.Substring(Math.Max(0,block.Length-128));
                                if(clock.Elapsed.TotalSeconds>=nextProgress) {
                                    Console.WriteLine("  PID "+pid+": "+(total/1048576)+" MiB analysed ("+(int)clock.Elapsed.TotalSeconds+" s)");
                                    nextProgress=(long)clock.Elapsed.TotalSeconds+3;
                                }
                            }
                            if(n<size){failures++;tail="";}
                            pos+=size;
                        }
                    } else tail="";
                    address=end;
                }
                Log("JVM "+pid+": "+(total/1048576)+" MiB read; partial/unreadable chunks "+failures+"; time limit reached: "+(clock.Elapsed.TotalSeconds>=60));
            } finally { CloseHandle(h); }
        }
    }
    [DllImport("ntdll.dll")] static extern int RtlDecompressBufferEx(ushort format,byte[] dst,int capacity,byte[] src,int size,out int written,byte[] workspace);
    [DllImport("ntdll.dll")] static extern int RtlGetCompressionWorkSpaceSize(ushort format,out int compress,out int decompress);
    static byte[] Unpack(byte[] b) {
        if(b.Length<8) return null;
        if(Bytes.GetString(b,0,3)!="MAM") return b;
        int capacity=BitConverter.ToInt32(b,4),c,d,w;
        if(b[3]!=4 || capacity<=0 || capacity>32*1024*1024 || RtlGetCompressionWorkSpaceSize(4,out c,out d)!=0) return null;
        byte[] output=new byte[capacity], src=new byte[b.Length-8];
        Buffer.BlockCopy(b,8,src,0,src.Length);
        return RtlDecompressBufferEx(4,output,capacity,src,src.Length,out w,new byte[Math.Max(c,d)])==0 && w==capacity ? output:null;
    }
    static void Prefetch() {
        int read=0, skipped=0, references=0;
        var checkedPaths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var f in Directory.EnumerateFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"Prefetch"),"*.pf")) {
            string name=Path.GetFileName(f);
            if(name.StartsWith(OriginalExe+"-",StringComparison.OrdinalIgnoreCase)) Hit("REVIEW | Original EXE name in Prefetch | "+name+" | name only");
            try {
                if(new FileInfo(f).Length>32*1024*1024){skipped++;continue;}
                byte[] b=Unpack(File.ReadAllBytes(f));
                if(b==null || b.Length<108 || Bytes.GetString(b,4,4)!="SCCA"){skipped++;continue;}
                int offset=BitConverter.ToInt32(b,100), length=BitConverter.ToInt32(b,104);
                if(offset<0 || length<0 || (length%2)!=0 || (long)offset+length>b.Length){skipped++;continue;}
                read++;
                foreach(string s in Encoding.Unicode.GetString(b,offset,length).Split('\0')) {
                    if(Original(s) || String.Equals(Path.GetFileName(s),"taskflow-2.5.15.jar",StringComparison.OrdinalIgnoreCase)) Hit("REVIEW | Prefetch filename lead | "+name+" | "+s+" | filename evidence only");
                    if(!s.EndsWith(".jar",StringComparison.OrdinalIgnoreCase)) continue;
                    references++;
                    // Prefetch commonly uses volume-relative names. Verify the volume before opening a referenced file.
                    foreach(var drive in DriveInfo.GetDrives()) {
                        if(drive.DriveType!=DriveType.Fixed) continue;
                        string letter=drive.Name.Substring(0,2);
                        var device=new StringBuilder(1024);
                        if(QueryDosDevice(letter,device,device.Capacity)==0) continue;
                        string prefix=device.ToString()+"\\";
                        string path=s.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)?letter+"\\"+s.Substring(prefix.Length):null;
                        if(s.StartsWith(letter+"\\",StringComparison.OrdinalIgnoreCase)) path=s;
                        if(path==null || !checkedPaths.Add(path) || !File.Exists(path)) continue;
                        try {
                            if(new FileInfo(path).Length<=4*1024*1024 && LoaderStructure(path))
                                Hit("REVIEW | Prefetch-referenced JAR currently matches loader structure | "+name+" | "+path);
                        } catch(InvalidDataException){skipped++;}
                    }
                }
            } catch(IOException){skipped++;} catch(UnauthorizedAccessException){skipped++;}
        }
        Log("Prefetch records parsed: "+read+"; JAR references: "+references+"; resolved JAR paths checked or attempted: "+checkedPaths.Count+"; skips/errors: "+skipped);
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint QueryDosDevice(string device,StringBuilder target,int size);
    static void Events() {
        const string channel="Microsoft-Windows-Sysmon/Operational";
        var known=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // First pass establishes identity, irrespective of how recently a later event was written.
        foreach(var ids in new[]{new[]{1},new[]{8,22,23,26}}) {
            string query="*[System[("+String.Join(" or ",ids.Select(i=>"EventID="+i))+") and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
            var q=new EventLogQuery(channel,PathType.LogName,query){ReverseDirection=true};
            int records=0;
            using(var reader=new EventLogReader(q)) {
                EventRecord e;
                while(records<50000 && (e=reader.ReadEvent())!=null) using(e) {
                    records++;
                    var values=XDocument.Parse(e.ToXml()).Descendants().Where(x=>x.Name.LocalName=="Data" && x.Attribute("Name")!=null).ToDictionary(x=>(string)x.Attribute("Name"),x=>x.Value);
                    Func<string,string> v=k=>values.ContainsKey(k)?values[k]:"";
                    string kind=Sample(v("Hashes")), id=v("ProcessGuid"), target=v("TargetFilename");
                    string when=e.TimeCreated.HasValue?e.TimeCreated.Value.ToUniversalTime().ToString("u"):"time unknown";
                    string where=" | "+when+" | Sysmon "+e.Id+" record "+e.RecordId;
                    if(e.Id==1 && IsShell(v("Image"))) CheckCommand(v("CommandLine"),where);
                    if(e.Id==22 && v("QueryName").TrimEnd('.').Equals("prestigeclient.vip",StringComparison.OrdinalIgnoreCase))
                        Hit("REVIEW | Launcher domain DNS query by "+v("Image")+where+" | endpoint and execution unknown");
                    if(e.Id==1 && kind!=null) {
                        Hit("EXACT | "+kind+" process created | "+v("Image")+where);
                        if(id.Length>0) known.Add(id);
                    }
                    if(e.Id==22 && v("QueryName").TrimEnd('.').Equals(Host,StringComparison.OrdinalIgnoreCase))
                        Hit("REVIEW | Prestige domain queried by "+v("Image")+where);
                    if(e.Id==8 && Java(v("TargetImage"))) {
                        bool linked=known.Contains(v("SourceProcessGuid"));
                        Hit((linked?"LINKED":"GENERIC")+" | remote thread into Java | "+v("SourceImage")+" -> "+v("TargetImage")+" PID "+v("TargetProcessId")+where);
                    }
                    if((e.Id==23||e.Id==26) && (kind!=null||Original(target)||known.Contains(id))) {
                        string what=kind!=null?"Exact loader file deleted":known.Contains(id)?"Known loader deleted a file":"Original filename deleted";
                        Hit((kind!=null||known.Contains(id)?"LINKED":"REVIEW")+" | "+what+" | "+target+" | deleting process "+v("Image")+where);
                    }
                }
            }
            Log("Sysmon IDs "+String.Join(",",ids)+": "+records+" records examined over 7 days; record limit reached: "+(records==50000));
        }
        Log("Sysmon coverage depends on event types enabled at the time and retained records.");
    }
    static bool IsShell(string path) {
        string n=Path.GetFileName(path);
        return String.Equals(n,"powershell.exe",StringComparison.OrdinalIgnoreCase)||String.Equals(n,"pwsh.exe",StringComparison.OrdinalIgnoreCase);
    }
    static readonly Regex Endpoint=new Regex(@"https://prestigeclient\.vip/downloads/([rt])\.php(?=$|[\s'""?#)])",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    static readonly Regex Literal=new Regex(@"['""]([A-Za-z0-9+/=]{32,})['""]");
    static string ClassifyCommand(string command,int depth) {
        if(String.IsNullOrEmpty(command)||command.Length>1048576) return null;
        var endpoint=Endpoint.Match(command);
        if(endpoint.Success) {
            string route=endpoint.Groups[1].Value.ToLowerInvariant()+".php";
            return "REVIEW | Reported Prestige "+route+" endpoint in recorded text";
        }
        string normalized=command.Replace("\u0060","").ToLowerInvariant();
        if(!normalized.Contains("frombase64string") || !normalized.Contains("::reverse") ||
            !(normalized.Contains("iex")||normalized.Contains("invoke-expression"))) return null;
        if(depth<3) foreach(Match literal in Literal.Matches(command).Cast<Match>().Take(8)) {
            char[] reversed=literal.Groups[1].Value.ToCharArray(); Array.Reverse(reversed);
            string b64=new string(reversed).TrimEnd('=');
            if(b64.Length%4==1) b64=b64.Substring(0,b64.Length-1);
            try {
                byte[] bytes=Convert.FromBase64String(b64.PadRight((b64.Length+3)/4*4,'='));
                string inner=ClassifyCommand(Encoding.UTF8.GetString(bytes),depth+1);
                if(inner!=null && inner.StartsWith("REVIEW")) return inner+" (offline decoded)";
            } catch(FormatException) {}
        }
        return "GENERIC | Reverse/Base64 PowerShell wrapper; brand unverified";
    }
    static void CheckCommand(string data,string source) {
        string verdict=ClassifyCommand(data,0);
        if(verdict!=null) Hit(verdict+" | "+source);
    }
    static void History() {
        string baseDir=Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        foreach(string edition in new[]{"Windows\\PowerShell","PowerShell"}) {
            string path=Path.Combine(baseDir,"Microsoft",edition,"PSReadLine","ConsoleHost_history.txt");
            Run(edition+" console history",delegate {
                if(!File.Exists(path)){Log("No readable default history file.");return;}
                int line=0;
                foreach(string s in File.ReadLines(path)){line++;CheckCommand(s,edition+" console history line "+line+" (undated)");}
                Log("History lines examined: "+line);
            });
        }
        using(var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")) {
            if(key==null){Log("Run history unavailable for current user.");return;}
            foreach(string name in key.GetValueNames()) if(name.Length==1) CheckCommand(key.GetValue(name) as string,"Current user Win+R history, entry "+name+" (undated)");
        }
    }
    static void ShellLog(string channel,int eventId) {
        string query="*[System[EventID="+eventId+" and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        var q=new EventLogQuery(channel,PathType.LogName,query){ReverseDirection=true};
        int count=0;
        using(var reader=new EventLogReader(q)) {
            EventRecord e;
            while(count<50000 && (e=reader.ReadEvent())!=null) using(e) {
                count++;
                var fields=XDocument.Parse(e.ToXml()).Descendants().Where(x=>x.Name.LocalName=="Data");
                Func<string,string> field=k=>(string)fields.FirstOrDefault(x=>(string)x.Attribute("Name")==k)??"";
                if(eventId==4688 && !IsShell(field("NewProcessName"))) continue;
                CheckCommand(field(eventId==4688?"CommandLine":"ScriptBlockText"),channel+" event "+eventId+" record "+e.RecordId+" | "+(e.TimeCreated.HasValue?e.TimeCreated.Value.ToUniversalTime().ToString("u"):"time unknown"));
            }
        }
        Log("Records examined: "+count+" (7 days; limit 50000; split script blocks assessed individually)");
    }
    static void Run(string label, Action action) {
        Log(Environment.NewLine+"--- "+label+" ---");
        try {action();} catch(Exception e){Log("Coverage incomplete: "+e.Message);}
    }
    public static int Scan(string[] args,string outputDir) { Findings.Clear();
        try {
            string mode=args.Length>0?args[0]:Console.ReadLine();
            if(mode!="1" && mode!="2" && mode!="3"){Console.WriteLine("Choose 1, 2 or 3.");return 2;}
            string output=Path.Combine(outputDir,"Prestige-report-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,6)+".txt");
            using(report=new StreamWriter(new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.Read))) {
                report.AutoFlush=true;
                Log("Prestige Scanner | UTC "+DateTime.UtcNow.ToString("u")+" | mode "+mode);
                Log("EXACT = known loader bytes/hash; LINKED = attributed event; REVIEW/GENERIC = lead. No match cannot clear a player.");
                if(mode!="2") Run("Live Java memory",Memory);
                if(mode!="1") {
                    string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string[] roots=args.Length>1?args.Skip(1).ToArray():new[]{Path.Combine(user,"Downloads"),Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Path.GetTempPath(),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),".minecraft")};
                    Run("Exact sample scan",delegate {Log("Roots: "+String.Join(" | ",roots));Disk(roots);});
                    Run("Prefetch",Prefetch); Run("Event history",Events);
                    Run("PowerShell and Win+R history",History);
                    foreach(string channel in new[]{"Microsoft-Windows-PowerShell/Operational","PowerShellCore/Operational","Security"})
                        Run(channel,delegate {ShellLog(channel,channel=="Security"?4688:4104);});
                }
                Log("Distinct findings: "+Findings.Count+". Deletion alone does not establish self-destruction. A JVM may belong to another application.");
            }
            Console.WriteLine("Report: "+output);
            if(args.Length==0){Console.WriteLine("Press Enter to close.");Console.ReadLine();}
            return 0;
        } catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}
    }
}

'@
if (!('PrestigePowerShellScanner' -as [type])) {
    Add-Type -TypeDefinition $engine -ReferencedAssemblies 'System.dll','System.Core.dll','System.Xml.Linq.dll','System.Xml.dll','System.IO.Compression.dll'
}
$status = [PrestigePowerShellScanner]::Scan([string[]]@($Mode), $outputFolder)
if ($status -ne 0) { throw "Scanner exited with code $status." }


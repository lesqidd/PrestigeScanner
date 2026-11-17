#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('1','2','3')][string]$Mode = '3')

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline
    Write-Host 'Administrator privileges required!'
    Write-Host
    Write-Host 'Please launch CMD or PowerShell as admin!' -ForegroundColor Yellow
    return
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    throw 'Open 64-bit Windows PowerShell 5.1 as administrator to run this scanner.'
}

Write-Host '  PRESTIGE SCANNER  ' -ForegroundColor Black -BackgroundColor Cyan
Write-Host 'Starting scan...' -ForegroundColor Cyan

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

public class PrestigeConsoleScannerV9 {
    const string Jar = "c2a6f8fb26c88eb9fc823fc9dd8373f268cdacdc59b2b636ace353a9b0dc59f1";
    const string Exe = "d7508c0022d959e4566d2cc1742cc0b7752b6fd1e692ecab7cef7ac6b9d8eec3";
    const string Host = "api.prestigeclient.vip";
    const string OriginalExe = "icloudjsclownht2ogv.exe";
    const string OriginalJar = "lesqid is gay.jar";
    static readonly Encoding Bytes = Encoding.GetEncoding(28591);
    static readonly HashSet<string> Findings = new HashSet<string>();
    static HashSet<int> gamePids=new HashSet<int>();
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr handle,out uint mode);
    static bool OrangeSupported() { uint mode; return GetConsoleMode(GetStdHandle(-11),out mode) && (mode&4)!=0; }
    static int gaps, shown;
    static void Paint(string text,ConsoleColor color,bool highlight=false,bool orange=false) {
        if(Console.IsOutputRedirected){Console.WriteLine(text);return;}
        var fg=Console.ForegroundColor;var bg=Console.BackgroundColor;
        try {
            if(highlight){Console.BackgroundColor=ConsoleColor.DarkRed;Console.ForegroundColor=ConsoleColor.White;}
            else Console.ForegroundColor=color;
            if(orange && OrangeSupported()) Console.WriteLine("\u001b[1;38;2;255;165;0m"+text+"\u001b[0m");
            else Console.WriteLine(text);
        } finally {Console.BackgroundColor=bg;Console.ForegroundColor=fg;}
    }
    static void Log(string s) {
        if(s.StartsWith("Coverage incomplete")||s.StartsWith("Unavailable:")){gaps++;return;}
        if(s.StartsWith("MINECRAFT CLIENT | scanning")){Paint(s.Replace("MINECRAFT CLIENT | scanning live PID","Scanning Minecraft PID"),ConsoleColor.Cyan);return;}
        if(s.StartsWith("Live Java processes: 0")){Paint("No running Java process found.",ConsoleColor.Yellow);return;}
        if(s.StartsWith("EXACT |")) {
            string detail=Regex.Replace(s.Substring(8),@" \| [0-9a-fA-F]{64}$","");
            Paint(" EXACT MATCH  "+detail,ConsoleColor.White,true);shown++;return;
        }
        if(s.StartsWith("FILE INDICATOR |")){Paint(" FILE CLUE  "+s.Substring(17),ConsoleColor.DarkYellow,false,true);shown++;return;}
        if(s.StartsWith("LINKED |") || (s.StartsWith("REVIEW |") &&
            (s.Contains("Minecraft PID") || s.Contains("in Minecraft memory") || s.Contains("Running Minecraft session") || s.Contains("JVM PID") || s.Contains("in Java PID")))){
            Paint(" CHECK  "+s.Substring(s.IndexOf('|')+1).Trim(),ConsoleColor.Yellow);shown++;return;
        }
        if(s.StartsWith("Distinct findings:")){
            Paint("Scan complete",ConsoleColor.Cyan);
            if(shown==0) Paint("No priority matches surfaced.",ConsoleColor.Gray);
            if(gaps>0) Paint("Some checks were unavailable.",ConsoleColor.Yellow);
        }
    }
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
        using(var f=File.OpenRead(path)) using(var z=new ZipArchive(f,ZipArchiveMode.Read)) return LoaderStructure(z);
    }
    static bool LoaderStructure(ZipArchive z) {
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
    static readonly string[] Apis={"java/lang/ClassLoader","defineClass","javax/crypto/Cipher","java/net/","java/lang/reflect/","loadLibrary"};
    static string JarFileIndicator(string path) {
        // Inspect bounded, decompressed class data. Treat strings as supporting evidence only.
        using(var f=File.OpenRead(path)) using(var z=new ZipArchive(f,ZipArchiveMode.Read)) {
            if(LoaderStructure(z)) return "Known loader manifest and class structure";
            int budget=4*1024*1024; int traits=0;
            bool blob=z.Entries.Any(e=>e.Length>=256 && Regex.IsMatch(e.FullName,@"\.(enc|bin|dat)$",RegexOptions.IgnoreCase));
            byte[] block=new byte[65536+Overlap], chunk=new byte[65536];
            foreach(var entry in z.Entries) {
                if(!entry.FullName.EndsWith(".class",StringComparison.OrdinalIgnoreCase) || entry.Length<4) continue;
                int carry=0,mask=0;
                using(var stream=entry.Open()) {
                    while(budget>0) {
                        int n=stream.Read(chunk,0,Math.Min(chunk.Length,budget));
                        if(n==0)break;
                        Buffer.BlockCopy(chunk,0,block,carry,n); int length=carry+n;
                        mask=MatchBlock(block,length,mask);budget-=n;
                        string literals=Bytes.GetString(block,0,length);
                        for(int t=0;t<Apis.Length;t++) if((traits&(1<<t))==0 && literals.IndexOf(Apis[t],StringComparison.Ordinal)>=0)traits|=1<<t;
                        if((mask&3)!=0) return "Prestige loader endpoint in "+entry.FullName;
                        int pair=3<<Markers.Length;
                        if((mask&pair)==pair) return "Paired Prestige console strings in "+entry.FullName;
                        carry=Math.Min(length,Overlap);Buffer.BlockCopy(block,length-carry,block,0,carry);
                    }
                }
                if(budget==0)break;
            }
            if((traits&31)==31) return "GENERIC: class-definition, encryption, network and reflection API references"+((traits&32)!=0?"; native loading API":"")+(blob?"; binary resource present":"");
        }
        return null;
    }
    // Only learn class fingerprints from an archive whose full SHA-256 matches the verified loader.
    static readonly HashSet<string> RefClasses=new HashSet<string>();
    static HashSet<string> ClassHashes(string path) {
        var hashes=new HashSet<string>(); long remaining=4*1024*1024;
        using(var f=File.OpenRead(path)) using(var z=new ZipArchive(f,ZipArchiveMode.Read))
        using(var sha=SHA256.Create()) foreach(var e in z.Entries) {
            if(!e.FullName.EndsWith(".class",StringComparison.OrdinalIgnoreCase)||e.Length<64 || e.Length>remaining)continue;
            remaining-=e.Length;
            using(var st=e.Open())hashes.Add(BitConverter.ToString(sha.ComputeHash(st)));
            if(remaining<=0)break;
        }
        return hashes;
    }
    static void Disk(string[] roots) {
        int files=0, hashes=0, errors=0, links=0;
        RefClasses.Clear(); var jarCandidates=new List<string>();
        var pending=new Stack<FileSystemInfo>(roots.Select(p=>(FileSystemInfo)new DirectoryInfo(p)));
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while(pending.Count>0 && files<250000) {
            var item=pending.Pop(); string path=item.FullName;
            if(!seen.Add(path)) continue;
            try {
                var attr=item.Attributes;
                if((int)attr==-1){errors++;continue;}
                if((attr & FileAttributes.ReparsePoint)!=0) {links++; continue;}
                if((attr & FileAttributes.Directory)!=0) {
                    foreach(var child in ((DirectoryInfo)item).EnumerateFileSystemInfos()) pending.Push(child);
                    continue;
                }
                files++;
                var file=item as FileInfo;
                long length=file==null?new FileInfo(path).Length:file.Length;
                if(length==8119 || length==237848) {
                    hashes++;
                    using(var f=File.OpenRead(path)) using(var sha=SHA256.Create()) {
                        string h=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
                        string sample=Sample(h);
                        if(sample!=null){if(h.Equals(Jar,StringComparison.OrdinalIgnoreCase))RefClasses.UnionWith(ClassHashes(path));Hit("EXACT | "+sample+" on disk | "+path+" | "+h);continue;}
                    }
                }
                if(path.EndsWith(".jar",StringComparison.OrdinalIgnoreCase) && length<=4*1024*1024 && length>0) {
                    if(length<=128*1024 && jarCandidates.Count<2048)jarCandidates.Add(path);
                    try { string reason=JarFileIndicator(path); if(reason!=null)Hit((reason.StartsWith("GENERIC:")?"GENERIC | ":"FILE INDICATOR | ")+reason+" | "+path); }
                    catch(InvalidDataException){errors++;}
                }
            } catch(UnauthorizedAccessException){errors++;} catch(IOException){errors++;}
        }
        if(RefClasses.Count>=2) foreach(var path in jarCandidates) {
            try {int shared=ClassHashes(path).Count(RefClasses.Contains);
                if(shared>=2)Hit("FILE INDICATOR | "+shared+" identical class files shared with verified JAR loader | "+path);
            }catch(InvalidDataException){errors++;}catch(IOException){errors++;}catch(UnauthorizedAccessException){errors++;}
        }
        Log("Reference class fingerprints available: "+RefClasses.Count+"; small repack candidates retained: "+jarCandidates.Count+" (limit 2048)");
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
    // Skip positions whose trailing byte pair cannot end any marker prefix.
    static readonly string[] Labels = Markers.Concat(ConsoleLines).Concat(new[]{Host}).ToArray();
    static readonly int HostBit=1<<(Labels.Length-1);
    static readonly Dictionary<int,DateTime> GameStarts=new Dictionary<int,DateTime>();
    static readonly byte[][] Patterns = Labels.SelectMany(s => new[]{Encoding.ASCII.GetBytes(s),Encoding.Unicode.GetBytes(s)}).ToArray();
    static readonly int Window = Patterns.Min(p=>p.Length);
    static readonly int Overlap = Patterns.Max(p=>p.Length)-1;
    static readonly byte[] Shift = BuildShift();
    static int Pair(byte[] b,int i) { return (b[i-1]<<8)|b[i]; }
    static byte[] BuildShift() {
        var shifts=Enumerable.Repeat((byte)(Window-1),65536).ToArray();
        foreach(var p in Patterns)
            for(int i=1;i<Window;i++) {
                int key=Pair(p,i);
                shifts[key]=Math.Min(shifts[key],(byte)(Window-1-i));
            }
        return shifts;
    }
    static int MatchBlock(byte[] b,int n,int mask) {
        for(int end=Window-1; end<n;) {
            int shift=Shift[Pair(b,end)];
            if(shift>0) {end+=shift;continue;}
            int start=end-Window+1;
            for(int i=0;i<Patterns.Length;i++) {
                int bit=1<<(i/2);
                var p=Patterns[i];
                if((mask&bit)!=0 || start+p.Length>n || b[start]!=p[0]) continue;
                int j=1;
                while(j<p.Length && b[start+j]==p[j]) j++;
                if(j==p.Length) mask|=bit;
            }
            end++;
        }
        return mask;
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
        var processes=Process.GetProcessesByName("java").Concat(Process.GetProcessesByName("javaw")).OrderByDescending(p=>gamePids.Contains(p.Id)).ToArray();
        Log("Live Java processes: "+processes.Length+" (includes non-Minecraft JVMs)");
        foreach(var p in processes) using(p) {
            int pid=p.Id;
            string target=gamePids.Contains(pid)?"MINECRAFT CLIENT":"Java (client identity unconfirmed)";
            Log(target+" | scanning live PID "+pid);
            try { var start=p.StartTime.ToUniversalTime(); if(gamePids.Contains(pid)) GameStarts[pid]=start; Log("Java PID "+pid+" | start UTC "+start.ToString("u")+" | uptime "+(DateTime.UtcNow-start).ToString(@"d\.hh\:mm\:ss")); }
            catch(System.ComponentModel.Win32Exception){Log("Start time unavailable for PID "+pid);}
            catch(InvalidOperationException){Log("PID "+pid+" exited.");continue;}
            IntPtr h=OpenProcess(0x410,false,pid);
            if(h==IntPtr.Zero){Log("Unavailable: JVM PID "+pid+" could not be opened.");continue;}
            var moduleNames=new Dictionary<IntPtr,string>();var privateImages=new HashSet<IntPtr>();
            if(gamePids.Contains(pid)) try { foreach(ProcessModule module in p.Modules) using(module) moduleNames[module.BaseAddress]=module.ModuleName; }
            catch(System.ComponentModel.Win32Exception){Log("Coverage incomplete: native module enumeration PID "+pid);}
            catch(InvalidOperationException){Log("Coverage incomplete: process exited during module enumeration");}
            long address=0,total=0; IntPtr allocation=IntPtr.Zero;int localMask=0; int failures=0;
            int mask=0;
            var inspectedAllocations=new HashSet<IntPtr>();
            var clock=Stopwatch.StartNew();
            byte[] buf=new byte[512*1024];
            byte[] block=new byte[buf.Length+Overlap];
            int tail=0;
            try {
                Region r;
                while(clock.Elapsed.TotalSeconds<60 && VirtualQueryEx(h,new IntPtr(address),out r,(UIntPtr)Marshal.SizeOf(typeof(Region))).ToUInt64()>0) {
                    long end=checked(r.Base.ToInt64()+(long)r.Size.ToUInt64());
                    if(end<=address) break;
                    if(allocation!=r.AllocationBase){allocation=r.AllocationBase;localMask=0;tail=0;}
                    uint perm=r.Protect & 255;
                    if(r.State==0x1000 && r.Type==0x20000 && (r.Protect&256)==0 && perm>=16 &&
                        inspectedAllocations.Add(r.AllocationBase) && PrivateDll(h,r.AllocationBase))
                        { privateImages.Add(allocation); Hit("GENERIC | Private allocation with executable protection and DLL headers | PID "+pid+" | allocation 0x"+r.AllocationBase.ToInt64().ToString("X")+" | possible manual map; payload identity unknown"); }
                    if(r.State==0x1000 && (r.Protect&256)==0 && (perm==2||perm==4||perm==8||perm==32||perm==64||perm==128)) {
                        for(long pos=address;pos<end && clock.Elapsed.TotalSeconds<60;) {
                            int size=(int)Math.Min(buf.Length,end-pos);
                            UIntPtr count;
                            ReadProcessMemory(h,new IntPtr(pos),buf,(UIntPtr)size,out count);
                            int n=(int)count.ToUInt64();
                            if(n>0) {
                                Buffer.BlockCopy(buf,0,block,tail,n);
                                int length=tail+n;
                                int previous=mask;
                                int priorLocal=localMask;
                                localMask=MatchBlock(block,length,localMask);
                                mask|=localMask;
                                string moduleName;
                                if(gamePids.Contains(pid) && localMask!=priorLocal && (moduleNames.TryGetValue(allocation,out moduleName)||privateImages.Contains(allocation))) {
                                    int pair=3<<Markers.Length;
                                    bool strong=((localMask^priorLocal)&3)!=0 || ((localMask&pair)==pair && (priorLocal&pair)!=pair);
                                    if(strong || ((localMask^priorLocal)&HostBit)!=0)
                                        Hit((strong?"LINKED":"REVIEW")+" | Minecraft PID "+pid+" | "+(strong?"Prestige loader markers":"Prestige hostname")+" in "+(moduleName??"private DLL-like memory")+" at 0x"+allocation.ToInt64().ToString("X"));
                                }
                                for(int i=0;i<Markers.Length;i++)
                                    if(((mask^previous)&(1<<i))!=0)
                                        Hit("REVIEW | JVM PID "+pid+" contains loader marker | "+Markers[i]+" | string presence alone does not establish execution");
                                if(gamePids.Contains(pid) && (previous&HostBit)==0 && (mask&HostBit)!=0)
                                    Hit("REVIEW | Prestige API hostname in Minecraft memory | PID "+pid+" | hostname text alone does not confirm injection");
                                int pairMask=3<<Markers.Length;
                                if((previous&pairMask)!=pairMask && (mask&pairMask)==pairMask)
                                    Hit("REVIEW | Both reported Prestige Legacy console strings in Java PID "+pid+" | same-process text evidence; build and execution unverified");
                                total+=n;
                                tail=Math.Min(length,Overlap);
                                Buffer.BlockCopy(block,length-tail,block,0,tail);
                            }
                            if(n<size){failures++;tail=0;}
                            pos+=size;
                        }
                    } else tail=0;
                    address=end;
                }
                int markerCount=Markers.Where((m,i)=>(mask&(1<<i))!=0).Count();
                bool consolePair=(mask&(3<<Markers.Length))==(3<<Markers.Length);
                Log(target+" | PID "+pid+" | loader markers: "+markerCount+" | API hostname in memory: "+((mask&HostBit)!=0)+" | Prestige console pair: "+consolePair+" | "+(total/1048576)+" MiB read; partial/unreadable chunks "+failures+"; time limit reached: "+(clock.Elapsed.TotalSeconds>=60));
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
        var volumes=new Dictionary<string,string>();
        foreach(var d in DriveInfo.GetDrives()){
            if(d.DriveType!=DriveType.Fixed)continue;
            string letter=d.Name.Substring(0,2);var device=new StringBuilder(1024);
            if(QueryDosDevice(letter,device,device.Capacity)!=0)volumes[letter]=device.ToString()+"\\";
        }
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
                    foreach(var map in volumes) {
                        string letter=map.Key, prefix=map.Value;
                        string path=s.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)?letter+"\\"+s.Substring(prefix.Length):null;
                        if(s.StartsWith(letter+"\\",StringComparison.OrdinalIgnoreCase)) path=s;
                        if(path==null || !checkedPaths.Add(path) || !File.Exists(path)) continue;
                        try {
                            if(new FileInfo(path).Length<=4*1024*1024 && LoaderStructure(path))
                                Hit("FILE INDICATOR | Prefetch-referenced JAR currently matches loader structure | "+name+" | "+path);
                        } catch(InvalidDataException){skipped++;}
                    }
                }
            } catch(IOException){skipped++;} catch(UnauthorizedAccessException){skipped++;}
        }
        Log("Prefetch records parsed: "+read+"; JAR references: "+references+"; resolved JAR paths checked or attempted: "+checkedPaths.Count+"; skips/errors: "+skipped);
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint QueryDosDevice(string device,StringBuilder target,int size);
    static bool SameLiveProcess(int pid,DateTime start) {
        try {using(var p=Process.GetProcessById(pid)) return p.StartTime.ToUniversalTime()==start;}
        catch(ArgumentException){return false;} catch(InvalidOperationException){return false;} catch(System.ComponentModel.Win32Exception){return false;}
    }
    static void Events() {
        const string channel="Microsoft-Windows-Sysmon/Operational";
        var known=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var apiQueries=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
        var remoteThreads=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
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
                    if(e.Id==22 && v("QueryName").TrimEnd('.').Equals(Host,StringComparison.OrdinalIgnoreCase)) {
                        int queryPid; DateTime started;
                        bool current=Java(v("Image")) && int.TryParse(v("ProcessId"),out queryPid) &&
                            GameStarts.TryGetValue(queryPid,out started) && e.TimeCreated.HasValue &&
                            e.TimeCreated.Value.ToUniversalTime()>=started && SameLiveProcess(queryPid,started);
                        Hit("REVIEW | "+(current?"Running Minecraft session":"Process")+" queried Prestige API | "+v("Image")+" PID "+v("ProcessId")+where);
                    }
                    if(e.TimeCreated.HasValue) {
                        bool dns=e.Id==22 && Java(v("Image")) && String.Equals(v("QueryName").TrimEnd('.'),Host,StringComparison.OrdinalIgnoreCase);
                        bool thread=e.Id==8 && Java(v("TargetImage"));
                        if(dns || thread) {
                            string guid=dns?id:v("TargetProcessGuid"); DateTime other;
                            if(!String.IsNullOrEmpty(guid)) {
                                var currentMap=dns?apiQueries:remoteThreads;
                                var otherMap=dns?remoteThreads:apiQueries;
                                var time=e.TimeCreated.Value.ToUniversalTime();
                                if(otherMap.TryGetValue(guid,out other) && Math.Abs((time-other).TotalMinutes)<=5)
                                    Hit("LINKED | Remote thread and Prestige API DNS query within five minutes in the same Java process | "+guid+" | events at "+other.ToString("u")+" and "+time.ToString("u")+" | attribution requires review");
                                currentMap[guid]=time;
                            }
                        }
                    }
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
        if(label!=null) Log(Environment.NewLine+"--- "+label+" ---");
        try {action();} catch(Exception e){Log("Coverage incomplete: "+e.Message);}
    }
    public static int Scan(string[] args,int[] minecraftIds,string[] extra) { gaps=0; shown=0; Findings.Clear(); GameStarts.Clear(); gamePids=new HashSet<int>(minecraftIds);
        try {
            string mode=args.Length>0?args[0]:Console.ReadLine();
            if(mode!="1" && mode!="2" && mode!="3"){Console.WriteLine("Choose 1, 2 or 3.");return 2;}
            Log("Prestige Scanner | UTC "+DateTime.UtcNow.ToString("u")+" | mode "+mode);
            Log("EXACT = known loader bytes/hash; LINKED = attributed event; REVIEW/GENERIC = lead. No match cannot clear a player.");
            foreach(string line in extra) {
                if(line.StartsWith("EXACT |")||line.StartsWith("GENERIC |")||line.StartsWith("REVIEW |"))Hit(line);else Log(line);
            }
            if(mode!="2") Run("Live Java memory",Memory);
            if(mode!="1") {
                string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string[] roots=args.Length>1?args.Skip(1).ToArray():new[]{Path.Combine(user,"Downloads"),Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Path.GetTempPath(),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),".minecraft")};
                Paint("Checking files and history...",ConsoleColor.Cyan);
                Run(null,delegate {Disk(roots);});
                Run("Prefetch",Prefetch); Run("Event history",Events);
                Run("PowerShell and Win+R history",History);
                foreach(string channel in new[]{"Microsoft-Windows-PowerShell/Operational","PowerShellCore/Operational","Security"})
                    Run(channel,delegate {ShellLog(channel,channel=="Security"?4688:4104);});
            }
            Log("Distinct findings: "+Findings.Count+". Deletion alone does not establish self-destruction. A JVM may belong to another application.");
            if(args.Length==0){Console.WriteLine("Press Enter to close.");Console.ReadLine();}
            return 0;
        } catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}
    }
}

'@
if (!('PrestigeConsoleScannerV9' -as [type])) {
    Add-Type -TypeDefinition $engine -ReferencedAssemblies 'System.dll','System.Core.dll','System.Xml.Linq.dll','System.Xml.dll','System.IO.Compression.dll'
}
function Get-GameDiagnostics($row) {
    $gameId = [int]$row.ProcessId
    $cmd = [string]$row.CommandLine
    foreach ($flag in '-javaagent:', '-agentpath:', '-agentlib:') {
        if ($cmd.IndexOf($flag,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
            "GENERIC | Minecraft PID $gameId has JVM option $flag (legitimate agents also use this)"
        }
    }
    foreach ($match in [regex]::Matches($cmd,'(?i)(?:^|\s)"?-(?:javaagent:|jar\s+"?)([A-Z]:[^"\r\n]*?\.jar)(?=["=\s]|$)')) {
        $file = $match.Groups[1].Value
        try {
            if ((Get-Item -LiteralPath $file).Length -eq 8119 -and (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -eq 'c2a6f8fb26c88eb9fc823fc9dd8373f268cdacdc59b2b636ace353a9b0dc59f1') {
                "EXACT | Minecraft PID $gameId launch argument references a file currently matching the known JAR loader | $file"
            }
        } catch { "Coverage incomplete: launch-argument JAR unavailable for PID $gameId" }
    }
    # Use only the target runtime's installed, signed JDK diagnostic tool.
    $image = [string]$row.ExecutablePath
    $programs = [Environment]::GetFolderPath('ProgramFiles') + '\'
    if (!$image.StartsWith($programs,[StringComparison]::OrdinalIgnoreCase)) {
        "Coverage incomplete: class diagnostics require a matching signed JDK under Program Files for PID $gameId"
        return
    }
    $tool = Join-Path (Split-Path -Parent $image) 'jcmd.exe'
    if (!(Test-Path -LiteralPath $tool -PathType Leaf) -or (Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
        "Coverage incomplete: signed jcmd unavailable for PID $gameId"
        return
    }
    foreach ($query in 'VM.classloaders','VM.class_hierarchy net.taskflow.sched.TaskScheduler') {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$tool
        $info.Arguments="$gameId $query"
        $info.WorkingDirectory=Split-Path -Parent $tool
        $info.UseShellExecute=$false
        $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true
        $info.RedirectStandardError=$true
        foreach ($key in 'JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH') { $info.EnvironmentVariables.Remove($key) }
        $proc=[Diagnostics.Process]::Start($info)
        try {
            $stdout=$proc.StandardOutput.ReadToEndAsync()
            $stderr=$proc.StandardError.ReadToEndAsync()
            if (!$proc.WaitForExit(8000)) {
                try { $proc.Kill() } catch {}
                "Coverage incomplete: Java diagnostic timed out for PID $gameId"
                return
            }
            $data=$stdout.GetAwaiter().GetResult()
            if($proc.ExitCode -ne 0 -or $data -match '(?i)unknown diagnostic command|diagnosticcommandexception') { "Coverage incomplete: $query unavailable in PID $gameId"; continue }
            if($data -match '(?im)^\s*(?:[|+\- ]*)net[./]taskflow[./]sched[./]TaskScheduler(?:[/@$\s]|$)') {
                "REVIEW | Live JVM class or class loader matching the reference TaskScheduler name | PID $gameId | $query"
            } else { "Java diagnostics | PID $gameId | checked $query" }
        } finally {$proc.Dispose()}
    }
}
function Get-HistoricalIndicators {
    $names='(?i)icloudjsclownht2ogv\.exe|lesqid is gay\.jar|taskflow-2\.5\.15\.jar'
    $key='Registry::HKEY_LOCAL_MACHINE\Amcache\Root\InventoryApplicationFile'
    if(Test-Path -LiteralPath $key) {
        $items=@(Get-ChildItem -LiteralPath $key -ErrorAction Stop | Select-Object -First 20000)
        foreach($item in $items) {
            $path=[string]$item.GetValue('LowerCaseLongPath')
            if($path -match $names) {"REVIEW | Mounted Amcache inventory filename | $path"}
        }
        "Amcache inventory entries checked: $($items.Count) (limit 20000)"
    } else { 'Coverage incomplete: mounted Amcache inventory unavailable' }
    $cache=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction SilentlyContinue
    if($cache -and $cache.AppCompatCache -is [byte[]]) {
        $text=[Text.Encoding]::Unicode.GetString($cache.AppCompatCache)
        foreach($hit in [regex]::Matches($text,$names) | Select-Object -First 10) { "REVIEW | ShimCache filename string | $($hit.Value) | inventory lead only" }
    } else { 'Coverage incomplete: ShimCache value unavailable' }
    $log=Join-Path $env:APPDATA '.minecraft\logs\latest.log'
    if(Test-Path -LiteralPath $log) {
        $found=Get-Content -LiteralPath $log -Tail 10000 | Select-String -Pattern 'api\.prestigeclient\.vip|net[./]taskflow[./]sched[./]TaskScheduler' | Select-Object -First 1
        if($found){'REVIEW | Minecraft latest.log contains a known hostname or loader class name (chat and mod logs can contain text)'}
    }
    foreach($entry in @(@('Security',1102),@('System',104))) {
        try {
            $events=Get-WinEvent -FilterHashtable @{LogName=$entry[0];Id=$entry[1];StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction Stop
            foreach($ev in $events){ if($entry[1] -eq 104 -and $ev.ProviderName -ne 'Microsoft-Windows-Eventlog'){continue}; "GENERIC | Windows log-clearing event | $($entry[0]) record $($ev.RecordId) | $($ev.TimeCreated.ToUniversalTime().ToString('u')) | cause unknown" }
        } catch { if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){"Coverage incomplete: $($entry[0]) log-clear history unavailable"} }
    }
}

$minecraftIds = @()
$extra = New-Object 'System.Collections.Generic.List[string]'
if ($Mode -ne '2') {
    try {
        $java = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -Property ProcessId,CommandLine,ExecutablePath -ErrorAction Stop
        $clientEntry = '(?i)(?:^|\s|")(?:net\.minecraft\.client\.main\.Main|(?:net\.fabricmc\.loader(?:\.impl)?|org\.quiltmc\.loader\.impl)\.launch\.knot\.KnotClient)(?=\s|"|$)'
        $minecraftIds = @($java | Where-Object {
            $_.CommandLine -match $clientEntry -or
            $_.CommandLine -match '(?i)--launchTarget(?:\s+|=)"?(?:forgeclient|neoforgeclient|fmlclient)(?:\s|"|$)' -or
            ($_.CommandLine -match '(?i)--gameDir\b' -and $_.CommandLine -match '(?i)--assetsDir\b' -and $_.CommandLine -match '(?i)--assetIndex\b')
        } | ForEach-Object { $row=$_; try { foreach ($line in @(Get-GameDiagnostics $row)) {$extra.Add([string]$line)} } catch {$extra.Add("Coverage incomplete: Java diagnostic unavailable for PID $($row.ProcessId)")} ; [int]$row.ProcessId })
    } catch { Write-Host 'Minecraft identification unavailable. Checking all Java processes.' -ForegroundColor Yellow }
    if (!$minecraftIds.Count) { Write-Host 'No Minecraft client identified by launch arguments. Checking all Java processes.' -ForegroundColor Yellow }
}
if ($Mode -ne '1') {
    try { Get-HistoricalIndicators | ForEach-Object {$extra.Add([string]$_)} } catch {$extra.Add("Coverage incomplete: history inspection interrupted")}
}
$status = [PrestigeConsoleScannerV9]::Scan([string[]]@($Mode), [int[]]$minecraftIds, $extra.ToArray())
if ($status -ne 0) { throw "Scanner exited with code $status." }


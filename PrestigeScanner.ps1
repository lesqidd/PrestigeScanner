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

Write-Host 'PRESTIGE SCANNER' -ForegroundColor Cyan
Write-Host 'Credits ' -ForegroundColor Magenta -NoNewline
Write-Host 'Discord:LeSqid' -ForegroundColor Gray
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

public class PrestigeConsoleScannerV18 {
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
    static bool SupportsAnsi() { uint mode; return GetConsoleMode(GetStdHandle(-11),out mode) && (mode&4)!=0; }
    static void Paint(string label, ConsoleColor color, string detail="", bool bold=false, bool orange=false) {
        if(Console.IsOutputRedirected){Console.WriteLine(label+detail);return;}
        var original=Console.ForegroundColor;
        try {
            Console.ForegroundColor=color;
            if(bold && SupportsAnsi()){
                Console.Write(orange?"\u001b[1;38;2;255;165;0m":"\u001b[1m");
                Console.Write(label);
                Console.Write("\u001b[22m");
            } else Console.Write(label);
            Console.ForegroundColor=original;
            Console.WriteLine(detail);
        } finally {Console.ForegroundColor=original;}
    }
    static readonly object OutputLock=new object();
    static void Log(string s) { lock(OutputLock) LogLine(s); }
    static void LogLine(string s) {
        string line=s.TrimStart('\r','\n');
        if(line.StartsWith("--- ") && line.EndsWith(" ---")){
            Console.WriteLine();
            Paint(line,ConsoleColor.Cyan,bold:true);
            return;
        }
        int split=line.IndexOf(" | ",StringComparison.Ordinal);
        if(split>0){
            string kind=line.Substring(0,split);
            string detail=line.Substring(split);
            switch(kind){
                case "EXACT": Paint("[DIRECT PRESTIGE MATCH]",ConsoleColor.Red,detail,true);return;
                case "FILE INDICATOR": Paint("[FILE INDICATOR]",ConsoleColor.Yellow,detail,true,true);return;
                case "LINKED":
                    if(detail.StartsWith(" | Minecraft PID ",StringComparison.Ordinal)) Paint("[MINECRAFT TRACE]",ConsoleColor.Red,detail,true);
                    else Paint("[LINKED]",ConsoleColor.Magenta,detail,true);
                    return;
                case "REVIEW": Paint("[REVIEW]",ConsoleColor.Yellow,detail,true);return;
                case "GENERIC": Paint("[GENERIC]",ConsoleColor.DarkCyan,detail);return;
                case "MINECRAFT CLIENT": Paint(kind,ConsoleColor.Cyan,detail,true);return;
            }
        }
        if(line.StartsWith("Coverage incomplete:") || line.StartsWith("Unavailable:"))
            Paint("[UNAVAILABLE]",ConsoleColor.DarkYellow," "+line.Substring(line.IndexOf(':')+1).TrimStart());
        else if(line.StartsWith("Distinct findings:"))
            Paint("Distinct findings:",ConsoleColor.White,line.Substring("Distinct findings:".Length),true);
        else Paint(line,ConsoleColor.Gray);
    }
    static void Hit(string s) { lock(OutputLock) if (Findings.Add(s)) LogLine(s); }
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
    static readonly byte[][] ApiBytes=Apis.Select(a=>Encoding.ASCII.GetBytes(a)).ToArray();
    // Match API names directly against class bytes.
    static int MatchApis(byte[] bytes,int length,int found) {
        for(int i=0;i<length && found!=63;i++) {
            byte first=bytes[i];
            if(first!=106 && first!=100 && first!=108)continue;
            for(int t=0;t<ApiBytes.Length;t++) {
                int bit=1<<t;var needle=ApiBytes[t];
                if((found&bit)!=0 || first!=needle[0] || length-i<needle.Length)continue;
                int j=1;while(j<needle.Length && bytes[i+j]==needle[j])j++;
                if(j==needle.Length)found|=bit;
            }
        }
        return found;
    }
    static string JarFileIndicator(string path) {
        // Limit decompressed class data to bound memory use.
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
                        traits=MatchApis(block,length,traits);
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
    // Seed class hashes only from a JAR matching the reference SHA-256.
    static readonly HashSet<string> RefClasses=new HashSet<string>();
    static readonly HashSet<long> ReferenceLengths=new HashSet<long>();
    static HashSet<string> ClassHashes(string path,bool reference=false) {
        var hashes=new HashSet<string>(); long remaining=4*1024*1024;
        using(var f=File.OpenRead(path)) using(var z=new ZipArchive(f,ZipArchiveMode.Read))
        using(var sha=SHA256.Create()) foreach(var e in z.Entries) {
            if(!e.FullName.EndsWith(".class",StringComparison.OrdinalIgnoreCase)||e.Length<64 || e.Length>remaining)continue;
            remaining-=e.Length;
            if(reference)ReferenceLengths.Add(e.Length);
            else if(!ReferenceLengths.Contains(e.Length))continue;
            using(var st=e.Open())hashes.Add(BitConverter.ToString(sha.ComputeHash(st)));
            if(remaining<=0)break;
        }
        return hashes;
    }
    static void Disk(string[] roots) {
        int files=0, hashes=0, errors=0, links=0;
        ReferenceLengths.Clear(); RefClasses.Clear(); var jarCandidates=new List<string>();
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
                        if(sample!=null){if(h.Equals(Jar,StringComparison.OrdinalIgnoreCase))RefClasses.UnionWith(ClassHashes(path,true));Hit("EXACT | "+sample+" on disk | "+path+" | "+h);continue;}
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
    // Use byte-pair shifts to skip impossible matches.
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
    sealed class MarkedRegion {
        public long Start,End;
        public string Name;
    }
    static readonly Dictionary<int,Dictionary<long,MarkedRegion>> MarkedRegions=new Dictionary<int,Dictionary<long,MarkedRegion>>();
    static void RecordNativeRegion(int pid,IntPtr allocation,long end,string name) {
        Dictionary<long,MarkedRegion> regions;
        if(!MarkedRegions.TryGetValue(pid,out regions)) MarkedRegions[pid]=regions=new Dictionary<long,MarkedRegion>();
        long start=allocation.ToInt64();
        regions[start]=new MarkedRegion{Start=start,End=end,Name=name};
    }
    static string RegionAt(int pid,string address) {
        Dictionary<long,MarkedRegion> regions;long start;
        if(!address.StartsWith("0x",StringComparison.OrdinalIgnoreCase) || !MarkedRegions.TryGetValue(pid,out regions) ||
            !long.TryParse(address.Substring(2),System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out start))return null;
        foreach(var r in regions.Values) if(start>=r.Start && start<r.End)return r.Name;
        return null;
    }
    static readonly Dictionary<int,long> LoadedSchedulerPids=new Dictionary<int,long>();
    static int NativeTraceLevel(int mask) {
        int legacyPair=3<<Markers.Length;
        if((mask&3)!=0 || (mask&legacyPair)==legacyPair) return 2;
        return (mask&HostBit)!=0?1:0;
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
            int reportedNativeLevel=0;
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
                    if(allocation!=r.AllocationBase){allocation=r.AllocationBase;localMask=0;reportedNativeLevel=0;tail=0;}
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
                            if(n==0 && size>Environment.SystemPageSize){
                                // Retry one page when a larger read fails.
                                size=Math.Min(size,Environment.SystemPageSize-(int)(pos%Environment.SystemPageSize));
                                ReadProcessMemory(h,new IntPtr(pos),buf,(UIntPtr)size,out count);
                                n=(int)count.ToUInt64();
                            }
                            if(n>0) {
                                Buffer.BlockCopy(buf,0,block,tail,n);
                                int length=tail+n;
                                int previous=mask;
                                localMask=MatchBlock(block,length,localMask);
                                mask|=localMask;
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
                            if(n<size)failures++;
                            if(n==0)tail=0;
                            pos+=n>0?n:size;
                        }
                    } else tail=0;
                    string backing;
                    if(gamePids.Contains(pid) && localMask!=0 &&
                        (moduleNames.TryGetValue(allocation,out backing)||privateImages.Contains(allocation))){
                        int level=NativeTraceLevel(localMask);
                        if(level>reportedNativeLevel){
                            reportedNativeLevel=level;
                            Hit((level==2?"LINKED":"REVIEW")+" | Minecraft PID "+pid+" | "+
                                (level==2?"Prestige loader endpoint or paired legacy markers":"Prestige hostname")+
                                " in "+(backing??"private DLL-like memory")+" at 0x"+allocation.ToInt64().ToString("X"));
                        }
                        if(level>0) RecordNativeRegion(pid,allocation,end,backing??"private DLL-like memory");
                    }
                    address=end;
                }
                if(MarkedRegions.ContainsKey(pid)) try {
                    var seenStarts=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach(ProcessThread thread in p.Threads) using(thread) {
                        try {
                            string owner=RegionAt(pid,"0x"+thread.StartAddress.ToInt64().ToString("X"));
                            if(owner!=null && seenStarts.Add(owner))
                                Hit("LINKED | Minecraft PID "+pid+" | live thread start in "+owner+" with a Prestige marker");
                        } catch(System.ComponentModel.Win32Exception){} catch(InvalidOperationException){}
                    }
                } catch(System.ComponentModel.Win32Exception){Log("Coverage incomplete: Minecraft thread check");}
                  catch(InvalidOperationException){Log("Coverage incomplete: Minecraft thread check");}
                long classStart; DateTime memoryStart;
                if(LoadedSchedulerPids.TryGetValue(pid,out classStart) && GameStarts.TryGetValue(pid,out memoryStart) && memoryStart.Ticks==classStart && (mask&HostBit)!=0)
                    Hit("LINKED | Minecraft PID "+pid+" | JVM reports TaskScheduler loaded and the Prestige API hostname was found in this process | injection unconfirmed");
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
                    // Resolve the Prefetch volume before opening the file.
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
    static void Events(string channel,PathType kindOfPath) {
        var known=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var apiQueries=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
        var remoteThreads=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
        // Collect process identities before correlating events.
        foreach(var ids in new[]{new[]{1},new[]{8,22,23,26}}) {
            string query="*[System[("+String.Join(" or ",ids.Select(i=>"EventID="+i))+") and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
            var q=new EventLogQuery(channel,kindOfPath,query){ReverseDirection=true};
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
                        int targetPid;DateTime targetStart;
                        if(int.TryParse(v("TargetProcessId"),out targetPid) && GameStarts.TryGetValue(targetPid,out targetStart) &&
                            e.TimeCreated.HasValue && e.TimeCreated.Value.ToUniversalTime()>=targetStart && SameLiveProcess(targetPid,targetStart)) {
                            string backing=RegionAt(targetPid,v("StartAddress"));
                            if(backing!=null)Hit("LINKED | Minecraft PID "+targetPid+" | remote thread from "+Path.GetFileName(v("SourceImage"))+" started at an address now in "+backing+" with a Prestige marker"+where);
                        }
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
    static void ReadAmcacheHive(string path) {
        using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
            if(f.ReadByte()!=114 || f.ReadByte()!=101 || f.ReadByte()!=103 || f.ReadByte()!=102)throw new InvalidDataException("Invalid hive header");
            string[] names={OriginalExe,OriginalJar,"taskflow-2.5.15.jar"};
            byte[] data=new byte[65536+256];int carry=0,n;
            while((n=f.Read(data,carry,65536))>0){
                int length=carry+n;
                for(int offset=0;offset<=1;offset++){
                    string view=Encoding.Unicode.GetString(data,offset,(length-offset)&~1);
                    foreach(string name in names)if(view.IndexOf(name,StringComparison.OrdinalIgnoreCase)>=0)
                        Hit("REVIEW | Amcache hive filename string | "+name+" | inventory lead only");
                }
                carry=Math.Min(256,length);Buffer.BlockCopy(data,length-carry,data,0,carry);
            }
        }
    }
    static void Amcache() {
        RegistryKey inventory=null;
        try {inventory=Registry.LocalMachine.OpenSubKey(@"Amcache\Root\InventoryApplicationFile");}
        catch(UnauthorizedAccessException){} catch(System.Security.SecurityException){}
        using(var root=inventory) {
            if(root==null){ReadAmcacheHive(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"appcompat","Programs","Amcache.hve"));return;}
            foreach(var name in root.GetSubKeyNames().Take(20000)) using(var item=root.OpenSubKey(name)) {
                string path=item==null?null:item.GetValue("LowerCaseLongPath") as string;
                if(path!=null && (Original(path)||path.EndsWith("taskflow-2.5.15.jar",StringComparison.OrdinalIgnoreCase)))
                    Hit("REVIEW | Mounted Amcache inventory filename | "+path);
            }
        }
    }
    static void ShellLog(string channel,int eventId,PathType kindOfPath) {
        string query="*[System[EventID="+eventId+" and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        var q=new EventLogQuery(channel,kindOfPath,query){ReverseDirection=true};
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
    static void WithEventFallback(string channel,Action<string,PathType> scan) {
        string reason;
        try {scan(channel,PathType.LogName);return;}
        catch(EventLogNotFoundException){reason="Windows could not find the live channel";}
        catch(EventLogException e){reason=e.Message;}
        catch(UnauthorizedAccessException){reason="Windows denied access to the live channel";}
        catch(System.Security.SecurityException){reason="Windows denied access to the live channel";}
        string dir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","winevt","Logs");
        string stem=channel.Replace("/","%4");
        var paths=new List<string>{Path.Combine(dir,stem+".evtx")};
        paths.AddRange(Directory.EnumerateFiles(dir,"Archive-"+stem+"-*.evtx").OrderByDescending(File.GetLastWriteTimeUtc).Take(4));
        bool readable=false;
        foreach(var path in paths) {
            if(!File.Exists(path))continue;
            try {scan(path,PathType.FilePath);readable=true;}
            catch(EventLogException){} catch(UnauthorizedAccessException){} catch(System.Security.SecurityException){}
        }
        if(!readable)throw new IOException(reason+". No readable saved log was found.");
    }
    static void Run(string label, Action action) {
        if(label!=null) Log(Environment.NewLine+"--- "+label+" ---");
        try {action();} catch(Exception e){Log("Coverage incomplete: "+(label??"File scan")+" - "+e.Message);}
    }
    public static int Scan(string[] args,int[] minecraftIds,string[] extra) { LoadedSchedulerPids.Clear(); MarkedRegions.Clear(); Findings.Clear(); GameStarts.Clear(); gamePids=new HashSet<int>(minecraftIds);
        try {
            string mode=args.Length>0?args[0]:Console.ReadLine();
            if(mode!="1" && mode!="2" && mode!="3"){Console.WriteLine("Choose 1, 2 or 3.");return 2;}
            Log("Prestige Scanner | UTC "+DateTime.UtcNow.ToString("u")+" | mode "+mode);
            Log("EXACT = known loader bytes/hash; LINKED = attributed event; REVIEW/GENERIC = lead. No match cannot clear a player.");
            foreach(string line in extra) {
                const string loaded="REVIEW | JVM reports the reference TaskScheduler class loaded | PID ";
                if(line.StartsWith(loaded,StringComparison.Ordinal)){
                    string[] identity=line.Substring(loaded.Length).Split('@');
                    int classPid; long startTicks;
                    if(identity.Length==2 && int.TryParse(identity[0],out classPid) && long.TryParse(identity[1],out startTicks) && gamePids.Contains(classPid)){
                        LoadedSchedulerPids[classPid]=startTicks;
                        Hit(loaded+classPid);
                        continue;
                    }
                }
                if(line.StartsWith("EXACT |")||line.StartsWith("GENERIC |")||line.StartsWith("REVIEW |"))Hit(line);else Log(line);
            }
            if(mode!="2") Run("Live Java memory",Memory);
            if(mode!="1") {
                string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string[] roots=args.Length>1?args.Skip(1).ToArray():new[]{Path.Combine(user,"Downloads"),Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Path.GetTempPath(),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),".minecraft")};
                Paint("Checking files and history...",ConsoleColor.Cyan);
                var disk=System.Threading.Tasks.Task.Factory.StartNew(delegate {Run(null,delegate {Disk(roots);});}, System.Threading.CancellationToken.None,System.Threading.Tasks.TaskCreationOptions.None,System.Threading.Tasks.TaskScheduler.Default);
                try {
                    Run("Amcache",Amcache); Run("Prefetch",Prefetch); Run("Sysmon",delegate {WithEventFallback("Microsoft-Windows-Sysmon/Operational",Events);});
                    Run("PowerShell and Win+R history",History);
                    foreach(string channel in new[]{"Microsoft-Windows-PowerShell/Operational","PowerShellCore/Operational","Security"})
                        Run(channel=="PowerShellCore/Operational"?"PowerShell 7 log":channel=="Security"?"Security log":"Windows PowerShell log",delegate {WithEventFallback(channel,delegate(string src,PathType type){ShellLog(src,channel=="Security"?4688:4104,type);});});
                } finally {disk.Wait();}
            }
            Log("Distinct findings: "+Findings.Count+". Deletion alone does not establish self-destruction. A JVM may belong to another application.");
            if(args.Length==0){Console.WriteLine("Press Enter to close.");Console.ReadLine();}
            return 0;
        } catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}
    }
}

'@
if (!('PrestigeConsoleScannerV18' -as [type])) {
    Add-Type -TypeDefinition $engine -ReferencedAssemblies 'System.dll','System.Core.dll','System.Xml.Linq.dll','System.Xml.dll','System.IO.Compression.dll'
}
function Find-JvmDiagnostic([string]$image) {
    if (!$image -or !(Test-Path -LiteralPath $image -PathType Leaf)) {return}
    $base=[Environment]::GetFolderPath('ProgramFiles')
    $targetBin=Split-Path -Parent $image
    $targetHome=Split-Path -Parent $targetBin
    $release=Join-Path $targetHome 'release'
    $major=''
    if(Test-Path -LiteralPath $release -PathType Leaf) {
        $versionLine=Get-Content -LiteralPath $release -TotalCount 80 | Where-Object {$_ -match '^JAVA_VERSION='} | Select-Object -First 1
        if($versionLine -match '^JAVA_VERSION="(?:1\.)?(\d+)'){$major=$Matches[1]}
    }
    $choices=@(Join-Path $targetBin 'jcmd.exe')
    if($major) {
        foreach($vendor in 'Java','Eclipse Adoptium','Microsoft','Zulu','Amazon Corretto','BellSoft') {
            $vendorDir=Join-Path $base $vendor
            if(!(Test-Path -LiteralPath $vendorDir -PathType Container)){continue}
            foreach($jdk in Get-ChildItem -LiteralPath $vendorDir -Directory -ErrorAction SilentlyContinue) {
                $choices+=Join-Path $jdk.FullName 'bin\jcmd.exe'
            }
        }
    }
    foreach($candidate in $choices | Select-Object -Unique) {
        if(!$candidate.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or !(Test-Path -LiteralPath $candidate -PathType Leaf)){continue}
        $node=Get-Item -LiteralPath $candidate
        if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
        $dir=$node.Directory
        while($dir -and !($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $dir.FullName -ne $base){$dir=$dir.Parent}
        if(!$dir -or $dir.FullName -ne $base){continue}
        if($candidate -ne $choices[0]) {
            $v=Get-Content -LiteralPath (Join-Path $node.Directory.Parent.FullName 'release') -TotalCount 80 -ErrorAction SilentlyContinue | Where-Object {$_ -match '^JAVA_VERSION='} | Select-Object -First 1
            if($v -notmatch '^JAVA_VERSION="(?:1\.)?(\d+)' -or $Matches[1] -ne $major){continue}
        }
        if((Get-AuthenticodeSignature -LiteralPath $candidate).Status -eq 'Valid'){return $candidate}
    }
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
    $image = [string]$row.ExecutablePath
    $tool = Find-JvmDiagnostic $image
    if (!$tool) {
        "Coverage incomplete: JVM class inspection (no matching local JDK)"
        return
    }
    $identityProcess=Get-Process -Id $gameId -ErrorAction Stop
    try { $startTicks=$identityProcess.StartTime.ToUniversalTime().Ticks } finally { $identityProcess.Dispose() }
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
            if($query -like 'VM.class_hierarchy *' -and $data -match '(?im)^[ \t|+\-]*net[./]taskflow[./]sched[./]TaskScheduler(?:[/@ \t].*)?\r?$') {
                "REVIEW | JVM reports the reference TaskScheduler class loaded | PID ${gameId}@$startTicks"
            } else { "Java diagnostics | PID $gameId | checked $query" }
        } finally {$proc.Dispose()}
    }
}
function Get-HistoricalIndicators {
    $names='(?i)icloudjsclownht2ogv\.exe|lesqid is gay\.jar|taskflow-2\.5\.15\.jar'
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
            $_.CommandLine -match '(?i)--launchTarget"?(?:\s+|=)"?(?:forgeclient|neoforgeclient|fmlclient)(?:\s|"|$)' -or
            ($_.CommandLine -match '(?i)(?:^|\s)"?net\.minecraft\.launchwrapper\.Launch"?(?=\s|$)' -and
             $_.CommandLine -match '(?i)(?:^|\s)"?--tweakClass"?(?:\s+|=)"?(?:net\.minecraftforge\.fml\.common\.launcher\.FMLTweaker|cpw\.mods\.fml\.common\.launcher\.FMLTweaker|optifine\.OptiFineTweaker)"?(?=\s|$)') -or
            ($_.CommandLine -match '(?i)--gameDir\b' -and $_.CommandLine -match '(?i)--assetsDir\b' -and $_.CommandLine -match '(?i)--assetIndex\b')
        } | ForEach-Object { $row=$_; try { foreach ($line in @(Get-GameDiagnostics $row)) {$extra.Add([string]$line)} } catch {$extra.Add("Coverage incomplete: Java diagnostic unavailable for PID $($row.ProcessId)")} ; [int]$row.ProcessId })
    } catch { Write-Host 'Minecraft identification unavailable. Checking all Java processes.' -ForegroundColor Yellow }
    if (!$minecraftIds.Count) { Write-Host 'No Minecraft client identified by launch arguments. Checking all Java processes.' -ForegroundColor Yellow }
}
if ($Mode -ne '1') {
    try { Get-HistoricalIndicators | ForEach-Object {$extra.Add([string]$_)} } catch {$extra.Add("Coverage incomplete: history inspection interrupted")}
}
$status = [PrestigeConsoleScannerV18]::Scan([string[]]@($Mode), [int[]]$minecraftIds, $extra.ToArray())
if ($status -ne 0) { throw "Scanner exited with code $status." }


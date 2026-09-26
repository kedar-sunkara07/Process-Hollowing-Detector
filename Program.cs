using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using System.IO;

class Program
{
    // kernel32
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);
    
    // psapi
    [DllImport("psapi.dll", SetLastError = true)]
    static extern uint GetMappedFileName(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);
    
    // ntdll
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    
    const uint PAGE_EXECUTE = 0x10;
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_IMAGE = 0x1000000;
    const uint MEM_PRIVATE = 0x20000;
    const uint MEM_MAPPED = 0x40000;

    static string GetProcessImagePath(IntPtr hProcess) {
        uint size = 1024;
        StringBuilder sb = new StringBuilder((int)size);
        if (QueryFullProcessImageName(hProcess, 0, sb, ref size)) {
            return sb.ToString();
        }
        return "";
    }

    static string GetMappedName(IntPtr hProcess, IntPtr address) {
        StringBuilder sb = new StringBuilder(1024);
        if (GetMappedFileName(hProcess, address, sb, 1024) > 0) {
            return sb.ToString();
        }
        return "";
    }

    static IntPtr GetPebImageBase(IntPtr hProcess) {
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        uint returnLength;
        int status = NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out returnLength);
        if (status == 0 && pbi.PebBaseAddress != IntPtr.Zero) {
            // PEB struct on x64: ImageBaseAddress is at offset 0x10
            // PEB struct on x86: ImageBaseAddress is at offset 0x08
            int offset = Environment.Is64BitProcess ? 0x10 : 0x08;
            byte[] buffer = new byte[IntPtr.Size];
            IntPtr read;
            if (ReadProcessMemory(hProcess, (IntPtr)((long)pbi.PebBaseAddress + offset), buffer, (uint)buffer.Length, out read)) {
                if (Environment.Is64BitProcess) {
                    return (IntPtr)BitConverter.ToInt64(buffer, 0);
                } else {
                    return (IntPtr)BitConverter.ToInt32(buffer, 0);
                }
            }
        }
        return IntPtr.Zero;
    }

    static bool IsValidPE(IntPtr hProcess, IntPtr baseAddress) {
        byte[] buffer = new byte[1024];
        IntPtr read;
        if (ReadProcessMemory(hProcess, baseAddress, buffer, 1024, out read) && read.ToInt64() > 0x40) {
            if (buffer[0] == 0x4D && buffer[1] == 0x5A) { // MZ
                int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                if (e_lfanew > 0 && e_lfanew < 1024 - 4) {
                    if (buffer[e_lfanew] == 0x50 && buffer[e_lfanew + 1] == 0x45) { // PE
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static void Main(string[] args)
    {
        Console.Title = "Process Hollowing Detector - Advanced Forensic Edition";
        while (true)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("========================================");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("ADVANCED PROCESS HOLLOWING DETECTOR");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("========================================");
            Console.ResetColor();
            Console.WriteLine("[1] Process Scan");
            Console.WriteLine("[2] Modules Scan");
            Console.WriteLine("[3] Exit");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("========================================");
            Console.ResetColor();
            Console.Write("\nSelect an option: ");
            string choice = Console.ReadLine();

            if (choice == "1") {
                RunScan(false);
            } else if (choice == "2") {
                RunScan(true);
            } else if (choice == "3") {
                break;
            }
        }
    }

    static void RunScan(bool moduleScan)
    {
        Console.Clear();
        Console.WriteLine("\nInitializing advanced forensic scan...");
        Console.WriteLine("----------------------------------------\n");
        
        List<Result> allResults = new List<Result>();
        int suspCount = 0;
        int cleanCount = 0;
        int deniedCount = 0;
        
        Process[] processes = Process.GetProcesses();
        foreach (Process p in processes) {
            int pid = p.Id;
            if (pid == 0 || pid == 4) continue;

            string processName = "";
            try { processName = p.ProcessName; } catch { processName = "Unknown"; }
            
            Result res = new Result { Pid = pid, Name = processName };
            
            Console.Write(string.Format("[{0,5}] Scanning {1,-25} ... ", pid, (processName.Length > 25 ? processName.Substring(0, 22) + "..." : processName)));
            
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) {
                res.Status = "ACCESS DENIED";
                allResults.Add(res);
                deniedCount++;
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("ACCESS DENIED");
                Console.ResetColor();
                continue;
            }

            res.Path = GetProcessImagePath(hProcess);
            IntPtr pebImageBase = GetPebImageBase(hProcess);
            
            long address = 0;
            long maxAddress = Environment.Is64BitProcess ? 0x7FFFFFFFFFFL : 0x7FFFFFFFL;
            
            bool foundMainImage = false;
            
            while (address < maxAddress) {
                MEMORY_BASIC_INFORMATION memInfo;
                int structSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                int read = VirtualQueryEx(hProcess, (IntPtr)address, out memInfo, (uint)structSize);
                
                if (read == 0) break;
                
                if (memInfo.State == MEM_COMMIT) {
                    bool isExecutable = (memInfo.Protect == PAGE_EXECUTE || 
                                         memInfo.Protect == PAGE_EXECUTE_READ || 
                                         memInfo.Protect == PAGE_EXECUTE_READWRITE || 
                                         memInfo.Protect == PAGE_EXECUTE_WRITECOPY);
                    
                    if (isExecutable || memInfo.BaseAddress == pebImageBase) {
                        string mappedFile = GetMappedName(hProcess, memInfo.BaseAddress);
                        
                        if (moduleScan && isExecutable) {
                            string rType = memInfo.Type == MEM_IMAGE ? "MEM_IMAGE" : (memInfo.Type == MEM_PRIVATE ? "MEM_PRIVATE" : "MEM_MAPPED");
                            res.Modules.Add(string.Format("Base: 0x{0}, Size: {1}, Type: {2}, Protect: 0x{3:X}, File: {4}", 
                                memInfo.BaseAddress.ToString("X"), 
                                (long)memInfo.RegionSize, 
                                rType, 
                                memInfo.Protect, 
                                mappedFile));
                        }

                        // ADVANCED HOLLOWING CHECKS
                        
                        // Check 1: PEB Image Base anomalies (Hollowed processes sometimes mess up PEB updates)
                        if (memInfo.BaseAddress == pebImageBase) {
                            foundMainImage = true;
                            
                            if (memInfo.Type != MEM_IMAGE) {
                                string ind = string.Format("PEB ImageBase (0x{0}) does not point to a valid MEM_IMAGE section", pebImageBase.ToString("X"));
                                if (!res.Indicators.Contains(ind)) res.Indicators.Add(ind);
                            }
                            
                            if (memInfo.Protect == PAGE_EXECUTE_READWRITE) {
                                string ind = "Main process image has PAGE_EXECUTE_READWRITE protection (Classic Hollowing)";
                                if (!res.Indicators.Contains(ind)) res.Indicators.Add(ind);
                            }
                        }

                        // Check 2: RWX in MEM_IMAGE (Modified Image)
                        if (memInfo.Type == MEM_IMAGE && memInfo.Protect == PAGE_EXECUTE_READWRITE) {
                            string ind = string.Format("Injected/Modified executable image (0x{0} is RWX)", memInfo.BaseAddress.ToString("X"));
                            if (!res.Indicators.Contains(ind)) res.Indicators.Add(ind);
                        }
                        
                        // Check 3: Private executable memory mapped as a valid PE file but completely unbacked
                        // This often indicates Reflective DLL Injection or manual PE mapping (similar to hollowing)
                        if (memInfo.Type == MEM_PRIVATE && memInfo.Protect == PAGE_EXECUTE_READWRITE) {
                            long baseAddr = (long)memInfo.AllocationBase;
                            
                            // Check for typical base addresses
                            if (baseAddr == 0x400000 || baseAddr == 0x140000000) {
                                string ind = "Suspicious process image anomaly (MEM_PRIVATE RWX at standard image base)";
                                if (!res.Indicators.Contains(ind)) res.Indicators.Add(ind);
                            }
                            
                            // Check if this unbacked region actually contains a PE header (Reflective mapping)
                            if (memInfo.BaseAddress == memInfo.AllocationBase && IsValidPE(hProcess, memInfo.BaseAddress)) {
                                string ind = string.Format("Unbacked PE image loaded in memory (Base: 0x{0}) - Possible Injection/Hollowing", memInfo.BaseAddress.ToString("X"));
                                if (!res.Indicators.Contains(ind)) res.Indicators.Add(ind);
                            }
                        }
                    }
                }
                
                address = (long)memInfo.BaseAddress + (long)memInfo.RegionSize;
            }
            
            CloseHandle(hProcess);
            
            if (res.Indicators.Count > 0) {
                res.Status = "SUSPICIOUS";
                suspCount++;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("SUSPICIOUS");
                Console.ResetColor();
            } else {
                res.Status = "CLEAN";
                cleanCount++;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("CLEAN");
                Console.ResetColor();
            }
            
            allResults.Add(res);
        }
        
        Console.WriteLine("\n----------------------------------------");
        if (suspCount == 0) {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No suspicious process hollowing indicators were detected.");
            Console.ResetColor();
        } else {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(string.Format("Warning: {0} suspicious processes found!", suspCount));
            Console.ResetColor();
            
            // Print out the suspicious ones clearly
            foreach(Result res in allResults) {
                if (res.Status == "SUSPICIOUS") {
                    Console.WriteLine(string.Format("\n> {0}.exe (PID: {1})", res.Name, res.Pid));
                    Console.WriteLine(string.Format("  Path: {0}", res.Path));
                    foreach(string ind in res.Indicators) {
                        Console.WriteLine("  - " + ind);
                    }
                }
            }
        }
        
        Console.WriteLine(string.Format("\nScan complete. Clean: {0}, Suspicious: {1}, Access Denied: {2}", cleanCount, suspCount, deniedCount));
        
        WriteReport(moduleScan ? "Modules Scan" : "Process Scan", allResults, suspCount == 0);
        
        Console.Write("\nPress ENTER to return to the main menu...");
        Console.ReadLine();
    }
    
    static void WriteReport(string scanType, List<Result> results, bool noSuspicious)
    {
        string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string reportPath = Path.Combine(downloadsPath, "report.txt");
        
        using (StreamWriter sw = new StreamWriter(reportPath, false, Encoding.UTF8))
        {
            sw.WriteLine("ADVANCED PROCESS HOLLOWING DETECTOR");
            sw.WriteLine("Scan time: " + DateTime.Now.ToString());
            sw.WriteLine("Scan type: " + scanType);
            sw.WriteLine();
            
            if (noSuspicious) {
                sw.WriteLine("No suspicious process hollowing indicators were detected.");
            } else {
                foreach(Result res in results) {
                    if (res.Status == "SUSPICIOUS" || res.Status == "ACCESS DENIED") {
                        sw.WriteLine("Process: " + res.Name);
                        sw.WriteLine("PID: " + res.Pid);
                        sw.WriteLine("Path: " + res.Path);
                        sw.WriteLine();
                        sw.WriteLine("Status: " + res.Status);
                        sw.WriteLine();
                        
                        if (res.Indicators.Count > 0) {
                            sw.WriteLine("Indicators:");
                            foreach(string ind in res.Indicators) {
                                sw.WriteLine("- " + ind);
                            }
                            sw.WriteLine();
                        }
                        
                        if (res.Modules.Count > 0) {
                            sw.WriteLine("Relevant information:");
                            foreach(string mod in res.Modules) {
                                sw.WriteLine("- " + mod);
                            }
                            sw.WriteLine();
                        }
                        
                        sw.WriteLine("========================================");
                        sw.WriteLine();
                    }
                }
            }
        }
        
        Console.WriteLine(string.Format("\nReport automatically saved to: {0}", reportPath));
    }
}

class Result {
    public int Pid;
    public string Name;
    public string Path = "";
    public string Status = "";
    public List<string> Indicators = new List<string>();
    public List<string> Modules = new List<string>();
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpShares.Enums
{
    class Shares
    {
        private const string CsvHeader = "TimestampUtc,Computer,Share,Path,Status,Readable,Writeable,CanListRoot,CanReadAcl,CanCreateFile,CanWriteFile,CanDeleteFile,CanCreateDirectory,CanDeleteDirectory,MatchingAllowRights,MatchingDenyRights,ReadError,AclError,FileWriteError,DirectoryWriteError,Notes";

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;

            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }

            public override string ToString()
            {
                return shi1_netname;
            }
        }

        private class ShareReport
        {
            public string TimestampUtc = DateTime.UtcNow.ToString("o");
            public string Computer;
            public string Share;
            public string Path;
            public string Status = "Unknown";
            public bool Readable;
            public bool Writeable;
            public bool CanListRoot;
            public bool CanReadAcl;
            public bool CanCreateFile;
            public bool CanWriteFile;
            public bool CanDeleteFile;
            public bool CanCreateDirectory;
            public bool CanDeleteDirectory;
            public string MatchingAllowRights = string.Empty;
            public string MatchingDenyRights = string.Empty;
            public string ReadError = string.Empty;
            public string AclError = string.Empty;
            public string FileWriteError = string.Empty;
            public string DirectoryWriteError = string.Empty;
            public string Notes = string.Empty;
        }

        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }

            ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
            return ShareInfos.ToArray();
        }

        public static void GetComputerShares(string computer, Utilities.Options.Arguments arguments)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            SHARE_INFO_1[] computerShares = EnumNetShares(computer);

            if (computerShares.Length > 0)
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (SHARE_INFO_1 share in computerShares)
                {
                    if ((arguments.filter != null) && (arguments.filter.Contains(share.shi1_netname.ToString().ToUpper())))
                    {
                        continue;
                    }

                    string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                    ShareReport report = new ShareReport
                    {
                        Computer = computer,
                        Share = share.shi1_netname,
                        Path = path
                    };

                    if (errors.Contains(share.shi1_netname))
                    {
                        report.Status = "EnumError";
                        report.Notes = share.shi1_netname;
                        WriteCsvReport(report, arguments.csv);
                        continue;
                    }

                    if (arguments.stealth)
                    {
                        WriteShareOutput(String.Format("[?] \\\\{0}\\{1}", computer, share.shi1_netname), arguments.outfile);
                        report.Status = "Unchecked";
                        report.Notes = "Stealth mode enabled; access checks skipped.";
                        WriteCsvReport(report, arguments.csv);
                        continue;
                    }

                    CheckShareAccess(report, identity);
                    WriteCsvReport(report, arguments.csv);

                    if (report.Readable)
                    {
                        WriteShareOutput(String.Format("[r] \\\\{0}\\{1}", computer, share.shi1_netname), arguments.outfile);
                    }

                    if (report.Writeable)
                    {
                        WriteShareOutput(String.Format("[w] \\\\{0}\\{1}", computer, share.shi1_netname), arguments.outfile);
                    }

                    if (arguments.verbose && !report.Readable && !report.Writeable)
                    {
                        WriteShareOutput(String.Format("[-] \\\\{0}\\{1}", computer, share.shi1_netname), arguments.outfile);
                    }
                }
            }

            Utilities.Status.currentCount += 1;
        }

        private static void CheckShareAccess(ShareReport report, WindowsIdentity identity)
        {
            try
            {
                Directory.GetFileSystemEntries(report.Path);
                report.CanListRoot = true;
                report.Readable = true;
                report.Status = "Readable";
            }
            catch (Exception ex)
            {
                report.ReadError = ex.Message;
                report.Status = "Unauthorized";
            }

            ReadAclDetails(report, identity);
            ProbeFileWrite(report);
            ProbeDirectoryWrite(report);

            if (report.CanCreateFile && report.CanWriteFile)
            {
                report.Writeable = true;
                report.Status = "Writeable";
            }
        }

        private static void ReadAclDetails(ShareReport report, WindowsIdentity identity)
        {
            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(report.Path).GetAccessRules(true, true, typeof(SecurityIdentifier));
                List<string> allowRights = new List<string>();
                List<string> denyRights = new List<string>();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (!IdentityMatches(rule.IdentityReference, identity))
                    {
                        continue;
                    }

                    string entry = String.Format("{0}:{1}", rule.IdentityReference, rule.FileSystemRights);
                    if (rule.AccessControlType == AccessControlType.Allow)
                    {
                        allowRights.Add(entry);
                    }
                    else if (rule.AccessControlType == AccessControlType.Deny)
                    {
                        denyRights.Add(entry);
                    }
                }

                report.CanReadAcl = true;
                report.MatchingAllowRights = String.Join(" | ", allowRights.ToArray());
                report.MatchingDenyRights = String.Join(" | ", denyRights.ToArray());
            }
            catch (Exception ex)
            {
                report.AclError = ex.Message;
            }
        }

        private static bool IdentityMatches(IdentityReference ruleIdentity, WindowsIdentity identity)
        {
            if (identity.User != null && ruleIdentity == identity.User)
            {
                return true;
            }

            return identity.Groups != null && identity.Groups.Contains(ruleIdentity);
        }

        private static void ProbeFileWrite(ShareReport report)
        {
            string filePath = Path.Combine(report.Path, ".SharpShares-" + Guid.NewGuid().ToString("N") + ".tmp");

            try
            {
                using (FileStream stream = new FileStream(filePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    report.CanCreateFile = true;
                    byte[] bytes = Encoding.ASCII.GetBytes("SharpShares write probe");
                    stream.Write(bytes, 0, bytes.Length);
                    report.CanWriteFile = true;
                }
            }
            catch (Exception ex)
            {
                report.FileWriteError = ex.Message;
            }

            if (report.CanCreateFile)
            {
                try
                {
                    File.Delete(filePath);
                    report.CanDeleteFile = true;
                }
                catch (Exception ex)
                {
                    AppendNote(report, "File cleanup failed: " + ex.Message);
                }
            }
        }

        private static void ProbeDirectoryWrite(ShareReport report)
        {
            string directoryPath = Path.Combine(report.Path, ".SharpShares-" + Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(directoryPath);
                report.CanCreateDirectory = true;
            }
            catch (Exception ex)
            {
                report.DirectoryWriteError = ex.Message;
            }

            if (report.CanCreateDirectory)
            {
                try
                {
                    Directory.Delete(directoryPath);
                    report.CanDeleteDirectory = true;
                }
                catch (Exception ex)
                {
                    AppendNote(report, "Directory cleanup failed: " + ex.Message);
                }
            }
        }

        private static void AppendNote(ShareReport report, string note)
        {
            if (String.IsNullOrEmpty(report.Notes))
            {
                report.Notes = note;
            }
            else
            {
                report.Notes += " " + note;
            }
        }

        private static void WriteShareOutput(string output, string outfile)
        {
            if (!String.IsNullOrEmpty(outfile))
            {
                try
                {
                    WriteToFileThreadSafe(output, outfile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Outfile Error: {0}", ex.Message);
                }
            }
            else
            {
                Console.WriteLine(output);
            }
        }

        public static void InitializeCsv(string path)
        {
            if (String.IsNullOrEmpty(path))
            {
                return;
            }

            using (StreamWriter sw = File.CreateText(path))
            {
                sw.WriteLine(CsvHeader);
            }
        }

        private static void WriteCsvReport(ShareReport report, string path)
        {
            if (String.IsNullOrEmpty(path))
            {
                return;
            }

            WriteToFileThreadSafe(ToCsv(report), path);
        }

        private static string ToCsv(ShareReport report)
        {
            string[] values =
            {
                report.TimestampUtc,
                report.Computer,
                report.Share,
                report.Path,
                report.Status,
                report.Readable.ToString(),
                report.Writeable.ToString(),
                report.CanListRoot.ToString(),
                report.CanReadAcl.ToString(),
                report.CanCreateFile.ToString(),
                report.CanWriteFile.ToString(),
                report.CanDeleteFile.ToString(),
                report.CanCreateDirectory.ToString(),
                report.CanDeleteDirectory.ToString(),
                report.MatchingAllowRights,
                report.MatchingDenyRights,
                report.ReadError,
                report.AclError,
                report.FileWriteError,
                report.DirectoryWriteError,
                report.Notes
            };

            return String.Join(",", values.Select(EscapeCsv).ToArray());
        }

        private static string EscapeCsv(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            bool mustQuote = value.Contains(",") || value.Contains("\"") || value.Contains("\r") || value.Contains("\n");
            value = value.Replace("\"", "\"\"");
            return mustQuote ? "\"" + value + "\"" : value;
        }

        public static ReaderWriterLockSlim _readWriteLock = new ReaderWriterLockSlim();

        public static void WriteToFileThreadSafe(string text, string path)
        {
            _readWriteLock.EnterWriteLock();
            try
            {
                using (StreamWriter sw = File.AppendText(path))
                {
                    sw.WriteLine(text);
                }
            }
            finally
            {
                _readWriteLock.ExitWriteLock();
            }
        }

        public static void GetAllShares(List<string> computers, Utilities.Options.Arguments arguments)
        {
            Console.WriteLine("[+] Starting share enumeration against {0} hosts\n", computers.Count);
            var threadList = new List<Action>();
            foreach (string computer in computers)
            {
                threadList.Add(() => GetComputerShares(computer, arguments));
            }
            var options = new ParallelOptions { MaxDegreeOfParallelism = arguments.threads };
            Parallel.Invoke(options, threadList.ToArray());
            Console.WriteLine("[+] Finished Enumerating Shares");
        }
    }
}

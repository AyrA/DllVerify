using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DllVerify
{
    public class Program
    {
        public const int EXIT_FAILED = -1;
        public const int EXIT_SUCCESS = 0;

        private class Arguments
        {
            public string FileName { get; private set; }
            public bool Help { get; private set; }
            public bool Verbose { get; private set; }
            public bool NoArgs { get; private set; }
            public bool Search { get; private set; }

            public Arguments(string[] args)
            {
                if (args == null || args.Length == 0)
                {
                    NoArgs = true;
                }
                else
                {
                    foreach (var a in args)
                    {
                        switch (a.ToLower())
                        {
                            case "/?":
                                if (Help)
                                {
                                    throw new ArgumentException($"Duplicate argument: {a.ToUpper()}");
                                }
                                Help = true;
                                break;
                            case "/v":
                                if (Verbose)
                                {
                                    throw new ArgumentException($"Duplicate argument: {a.ToUpper()}");
                                }
                                Verbose = true;
                                break;
                            case "/s":
                                if (Search)
                                {
                                    throw new ArgumentException($"Duplicate argument: {a.ToUpper()}");
                                }
                                Search = true;
                                break;
                            default:
                                if (FileName == null)
                                {
                                    FileName = a;
                                }
                                else
                                {
                                    throw new ArgumentException($"Unknown argument and file name already set: \"{a}\"");
                                }
                                break;
                        }
                    }
                }
            }
        }
        static int Main(string[] args)
        {
            Arguments A;
            try
            {
                A = new Arguments(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Unable to parse command line arguments. Reason:\r\n{0}", ex.Message);
                Console.Error.WriteLine("Use /? for help");
                return EXIT_FAILED;
            }
            if (A.NoArgs || A.Help)
            {
                Console.WriteLine(@"{0} <DllFile> [/V] [/S]
Checks if the given DLL file or executable has a valid signature.

/V   Verbose output
       Shows final DLL name when searching
       Shows search locations and exit codes when requesting help
/S   Search system for DLL file
       Search locations in order of preference:
       1. Application path
       2. Windows System32 directory
       3. Windows System directory
       4. Windows directory
       5. Current working directory (%CD%)
       6. Directories in the path variable (%PATH%)

Note: Searching will subject the file name to name changes,
similar to how Windows would do it.
Primarily, this means it adds '.dll' if it's not there.

Possible exit codes:
--------------------", GetProcName());
                var V = Enum.GetValues(typeof(Trust.WinVerifyTrustResult))
                    .OfType<Trust.WinVerifyTrustResult>()
                    .OrderBy(m => ToExit(m))
                    .ToArray();
                var Max = V.Max(m => m.ToString().Length);
                foreach (var E in V)
                {
                    Console.WriteLine("{0,-" + Max + "}: {1}", E, ToExit(E));
                }
                if (A.Verbose)
                {
                    Console.WriteLine();
                    Console.WriteLine("Search order (may contain duplicates):");
                    Console.WriteLine(string.Join("\n", GetDllSearchPath()));
                }
                return EXIT_SUCCESS;
            }
            else
            {
                try
                {
                    string RealName;
                    if (A.Search)
                    {
                        RealName = FindFullDllName(A.FileName);
                    }
                    else
                    {
                        RealName = Path.GetFullPath(A.FileName);
                    }
                    if (A.Verbose)
                    {
                        Console.WriteLine(RealName);
                    }
                    return ToExit(CheckDLL(RealName));
                }
                catch (FileNotFoundException)
                {
                    if (A.Search)
                    {
                        Console.Error.WriteLine("The given file could not be found in the search locations");
                    }
                    else
                    {
                        Console.Error.WriteLine($"The given file could not be found: {A.FileName}");
                    }
                }
            }
            return ToExit(Trust.WinVerifyTrustResult.ObjectNotFound);
        }

        /// <summary>
        /// Converts a verify result to an easier to manage exit code
        /// </summary>
        /// <param name="Result">DLL verify result</param>
        /// <returns>Exit code</returns>
        /// <remarks>
        /// Works as long as every value is unique
        /// </remarks>
        private static int ToExit(Trust.WinVerifyTrustResult Result)
        {
            return (int)Result & 0xFFFF;
        }

        /// <summary>
        /// Checks if the given DLL file name (or any executable) has a valid signature.
        /// </summary>
        /// <param name="DllFileName">DLL or executable file</param>
        /// <returns>Verification result</returns>
        private static Trust.WinVerifyTrustResult CheckDLL(string DllFileName)
        {
            return Trust.WinTrust.VerifyEmbeddedSignature(DllFileName);
        }

        /// <summary>
        /// Tries to find the full path of a given DLL file using the system default search order.
        /// If the supplied argument is a rooted path, it's used as-is.
        /// </summary>
        /// <param name="DllFile">DLL file name</param>
        /// <returns>Full path</returns>
        /// <exception cref="FileNotFoundException">Thrown if none of the searched paths contains the file name</exception>
        /// <remarks>
        /// This cannot handle a custom search path (those added via AddDllDirectory)
        /// and will only search in the system default order.
        /// Due to overlaps, this may search some locations twice.
        /// Order:
        /// 1. Application directory
        /// 2. Windows System32 directory
        /// 3. Windows System directory
        /// 4. Windows directory
        /// 5. Current Path (%CD%)
        /// 6. All directories in %PATH%
        /// </remarks>
        private static string FindFullDllName(string DllFile)
        {
            var Dirs = GetDllSearchPath();
            //Windows adds ".dll" if the extension is not present and the name doesn't ends with a dot
            if (!DllFile.ToLower().EndsWith(".dll"))
            {
                if (!DllFile.EndsWith("."))
                {
                    DllFile += ".dll";
                }
                else
                {
                    DllFile = DllFile.Substring(0, DllFile.Length - 1);
                }
            }
            if (Path.IsPathRooted(DllFile) && File.Exists(DllFile))
            {
                return Path.GetFullPath(DllFile);
            }
            var RealPath = Dirs.FirstOrDefault(m => File.Exists(Path.Combine(m, DllFile)));
            if (RealPath != null)
            {
                return Path.Combine(RealPath, DllFile);
            }
            var EX = new FileNotFoundException($"{DllFile} doesn't exists in the DLL search path. Check Exception data for directory list");
            EX.Data.Add("SearchOrder", Dirs);
            throw EX;
        }

        /// <summary>
        /// Gets all system DLL search paths in the order they will be searched
        /// </summary>
        /// <returns>Array of directories</returns>
        /// <remarks>This list may contain duplicates</remarks>
        private static string[] GetDllSearchPath()
        {
            var Dirs = new List<string>();
            Dirs.Add(Path.GetDirectoryName(GetProcPath()));
            Dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
            Dirs.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System"));
            Dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            Dirs.Add(Environment.CurrentDirectory);
            foreach (var P in Environment.GetEnvironmentVariable("PATH").Split(';'))
            {
                Dirs.Add(P);
            }
            return Dirs.ToArray();
        }

        /// <summary>
        /// Gets the executable file name of the current process
        /// </summary>
        /// <returns>Executable file name</returns>
        private static string GetProcName()
        {
            return Path.GetFileName(GetProcPath());
        }

        /// <summary>
        /// Gets the full path to the current executable file name
        /// </summary>
        /// <returns>full executable path</returns>
        private static string GetProcPath()
        {
            using (var P = System.Diagnostics.Process.GetCurrentProcess())
            {
                return P.MainModule.FileName;
            }
        }
    }
}

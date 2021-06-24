using System;
using System.Runtime.InteropServices;

namespace DllVerify.Trust
{
    /// <summary>
    /// Results of file signature verification
    /// </summary>
    public enum WinVerifyTrustResult : uint
    {
        /// <summary>
        /// Signature is present and considered valid by the operating system
        /// </summary>
        Success = 0,
        /// <summary>
        /// Trust provider is not recognized on this system
        /// </summary>
        ProviderUnknown = 0x800b0001,
        /// <summary>
        /// Trust provider does not support the specified action
        /// </summary>
        ActionUnknown = 0x800b0002,
        /// <summary>
        /// Trust provider does not support the form specified for the subject
        /// </summary>
        SubjectFormUnknown = 0x800b0003,
        /// <summary>
        /// Subject failed the specified verification action
        /// </summary>
        SubjectNotTrusted = 0x800b0004,
        /// <summary>
        /// TRUST_E_NOSIGNATURE - File was not signed
        /// </summary>
        FileNotSigned = 0x800B0100,
        /// <summary>
        /// Signer's certificate is in the Untrusted Publishers store
        /// </summary>
        SubjectExplicitlyDistrusted = 0x800B0111,
        /// <summary>
        /// TRUST_E_BAD_DIGEST - file was probably corrupt
        /// </summary>
        SignatureOrFileCorrupt = 0x80096010,
        /// <summary>
        /// CERT_E_EXPIRED - Signer's certificate was expired
        /// </summary>
        SubjectCertExpired = 0x800B0101,
        /// <summary>
        /// CERT_E_REVOKED Subject's certificate was revoked
        /// </summary>
        SubjectCertificateRevoked = 0x800B010C,
        /// <summary>
        /// CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
        /// </summary>
        UntrustedRoot = 0x800B0109,
        /// <summary>
        /// The specified object was not found
        /// </summary>
        /// <remarks>This is not an official code</remarks>
        ObjectNotFound = 0x80092003
    }

    /// <summary>
    /// Checks file signatures
    /// </summary>
    public static class WinTrust
    {
        #region WinTrustData struct field enums
        private enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        private enum WinTrustDataRevocationChecks : uint
        {
            None = 0x00000000,
            WholeChain = 0x00000001
        }

        private enum WinTrustDataChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }

        private enum WinTrustDataStateAction : uint
        {
            Ignore = 0x00000000,
            Verify = 0x00000001,
            Close = 0x00000002,
            AutoCache = 0x00000003,
            AutoCacheFlush = 0x00000004
        }

        [Flags]
        private enum WinTrustDataProvFlags : uint
        {
            UseIe4TrustFlag = 0x00000001,
            NoIe4ChainFlag = 0x00000002,
            NoPolicyUsageFlag = 0x00000004,
            RevocationCheckNone = 0x00000010,
            RevocationCheckEndCert = 0x00000020,
            RevocationCheckChain = 0x00000040,
            RevocationCheckChainExcludeRoot = 0x00000080,
            SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
            HashOnlyFlag = 0x00000200,
            UseDefaultOsverCheck = 0x00000400,
            LifetimeSigningFlag = 0x00000800,
            CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
            DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root
        }

        private enum WinTrustDataUIContext : uint
        {
            Execute = 0,
            Install = 1
        }
        #endregion

        #region WinTrust structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustFileInfo : IDisposable
        {
            uint StructSize = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
            IntPtr pszFilePath;                     // required, file name to be verified
            IntPtr hFile = IntPtr.Zero;             // optional, open handle to FilePath
            IntPtr pgKnownSubject = IntPtr.Zero;    // optional, subject type if it is known

            public WinTrustFileInfo(string _filePath)
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
            }
            public void Dispose()
            {
                if (pszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pszFilePath);
                    pszFilePath = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustData : IDisposable
        {
            uint StructSize = (uint)Marshal.SizeOf(typeof(WinTrustData));
            IntPtr PolicyCallbackData = IntPtr.Zero;
            IntPtr SIPClientData = IntPtr.Zero;
            // required: UI choice
            WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
            // required: certificate revocation check options
            WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
            // required: which structure is being passed in?
            WinTrustDataChoice UnionChoice = WinTrustDataChoice.File;
            // individual file
            IntPtr FileInfoPtr;
            WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
            IntPtr StateData = IntPtr.Zero;
            string URLReference = null;
            WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.RevocationCheckChainExcludeRoot;
            WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;

            // constructor for silent WinTrustDataChoice.File check
            public WinTrustData(WinTrustFileInfo _fileInfo)
            {
                // On Win7SP1+, don't allow MD2 or MD4 signatures
                if ((Environment.OSVersion.Version.Major > 6) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor > 1)) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1) && !string.IsNullOrEmpty(Environment.OSVersion.ServicePack)))
                {
                    ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
                }

                WinTrustFileInfo wtfiData = _fileInfo;
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
            }
            public void Dispose()
            {
                if (FileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(FileInfoPtr);
                    FileInfoPtr = IntPtr.Zero;
                }
            }
        }
        #endregion

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // GUID of the action to perform
        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern WinVerifyTrustResult WinVerifyTrust(
            [In] IntPtr hwnd,
            [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            [In] WinTrustData pWVTData
        );

        /// <summary>
        /// Verifies the file signature of an authenticode signed file
        /// </summary>
        /// <param name="fileName">File name and path</param>
        /// <returns>Verification result</returns>
        public static WinVerifyTrustResult VerifyEmbeddedSignature(string fileName)
        {
            using (WinTrustFileInfo wtfi = new WinTrustFileInfo(fileName))
            {
                using (WinTrustData wtd = new WinTrustData(wtfi))
                {
                    Guid guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                    return WinVerifyTrust(INVALID_HANDLE_VALUE, guidAction, wtd);
                }
            }
        }
    }
}

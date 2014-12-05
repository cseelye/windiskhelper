using System;
using System.Collections.Generic;
using System.Management;
using Microsoft.Storage.Vds;
using Microsoft.Storage.Vds.Advanced;
using System.Runtime.InteropServices;
using System.Threading;
using System.Linq;
using System.IO;
using System.Text.RegularExpressions;
using System.Text;
using System.ComponentModel;

using System.Security.Principal; // WindowsImpersonationContext

namespace windiskhelper
{
    class MicrosoftInitiator
    {
        static readonly List<string> DEFAULT_BLACKLISTED_MODELS = new List<string>()
        {
            "vmware",
            "idrac"
        };
        static readonly List<string> DEFAULT_WHITELISTED_MODELS = new List<string>();

        private List<string> mBlacklistedDiskModels;
        private List<string> mWhitelistedDiskModels;

        public MicrosoftInitiator(List<string> BlacklistedDiskModels = null, List<string> WhitelistedDiskModels = null)
        {
            if (BlacklistedDiskModels != null && BlacklistedDiskModels.Count() > 0)
                mBlacklistedDiskModels = BlacklistedDiskModels;
            else
                mBlacklistedDiskModels = DEFAULT_BLACKLISTED_MODELS;

            if (WhitelistedDiskModels != null && WhitelistedDiskModels.Count() > 0)
                mWhitelistedDiskModels = WhitelistedDiskModels;
            else
                mWhitelistedDiskModels = DEFAULT_WHITELISTED_MODELS;

            mClientHostname = "localhost";
        }

        public MicrosoftInitiator(string Hostname, string Username, string Password, List<string> BlacklistedDiskModels = null, List<string> WhitelistedDiskModels = null)
            : this(BlacklistedDiskModels, WhitelistedDiskModels)
        {
            mClientHostname = Hostname;
            mClientUsername = Username;
            mClientPassword = Password;
        }

        #region Infrastructure for remote connections/impersonation

        // obtains user token
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(string pszUsername, string pszDomain, string pszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        // closes open handes returned by LogonUser
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        // creates duplicate token handle
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        private enum SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        }
        public enum LogonType
        {
            /// <summary>
            /// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
            /// by a terminal server, remote shell, or similar process.
            /// This logon type has the additional expense of caching logon information for disconnected operations; 
            /// therefore, it is inappropriate for some client/server applications,
            /// such as a mail server.
            /// </summary>
            LOGON32_LOGON_INTERACTIVE = 2,

            /// <summary>
            /// This logon type is intended for high performance servers to authenticate plaintext passwords.

            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_NETWORK = 3,

            /// <summary>
            /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without 
            /// their direct intervention. This type is also for higher performance servers that process many plaintext
            /// authentication attempts at a time, such as mail or Web servers. 
            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_BATCH = 4,

            /// <summary>
            /// Indicates a service-type logon. The account provided must have the service privilege enabled. 
            /// </summary>
            LOGON32_LOGON_SERVICE = 5,

            /// <summary>
            /// This logon type is for GINA DLLs that log on users who will be interactively using the computer. 
            /// This logon type can generate a unique audit record that shows when the workstation was unlocked. 
            /// </summary>
            LOGON32_LOGON_UNLOCK = 7,

            /// <summary>
            /// This logon type preserves the name and password in the authentication package, which allows the server to make 
            /// connections to other network servers while impersonating the client. A server can accept plaintext credentials 
            /// from a client, call LogonUser, verify that the user can access the system across the network, and still 
            /// communicate with other servers.
            /// NOTE: Windows NT:  This value is not supported. 
            /// </summary>
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

            /// <summary>
            /// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
            /// The new logon session has the same local identifier but uses different credentials for other network connections. 
            /// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
            /// NOTE: Windows NT:  This value is not supported. 
            /// </summary>
            LOGON32_LOGON_NEW_CREDENTIALS = 9,
        }
        public enum LogonProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        private Dictionary<string, ManagementScope> wmiConnections = new Dictionary<string, ManagementScope>();
        private string mClientHostname;
        private string mClientUsername;
        private string mClientPassword;
        private Service mVdsService;
        private WindowsImpersonationContext mRemoteIdentity;

        private void StartImpersonation()
        {
            IntPtr pExistingTokenHandle = new IntPtr(0);
            IntPtr pDuplicateTokenHandle = new IntPtr(0);
            pExistingTokenHandle = IntPtr.Zero;
            pDuplicateTokenHandle = IntPtr.Zero;

            string user = mClientUsername;
            string domain = null;
            if (mClientUsername.Contains(@"\"))
            {
                string[] pieces = mClientUsername.Split('\\');
                domain = pieces[0];
                user = pieces[1];
            }

            try
            {
                // get handle to token
                Logger.Debug("Starting impersonation on " + mClientHostname + " as " + domain + "\\" + user + ":" + mClientPassword);
                bool bImpersonated = LogonUser(user, domain, mClientPassword,
                    (int)LogonType.LOGON32_LOGON_INTERACTIVE, (int)LogonProvider.LOGON32_PROVIDER_DEFAULT, ref pExistingTokenHandle);

                // did impersonation fail?
                if (false == bImpersonated)
                {
                    int nErrorCode = Marshal.GetLastWin32Error();
                    throw new InitiatorException((new System.ComponentModel.Win32Exception(nErrorCode)).Message);
                }

                bool bRetVal = DuplicateToken(pExistingTokenHandle, (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ref pDuplicateTokenHandle);

                // did DuplicateToken fail?
                if (false == bRetVal)
                {
                    int nErrorCode = Marshal.GetLastWin32Error();
                    throw new InitiatorException((new System.ComponentModel.Win32Exception(nErrorCode)).Message);
                }
                else
                {
                    // create new identity using new primary token
                    WindowsIdentity newId = new WindowsIdentity(pDuplicateTokenHandle);
                    WindowsImpersonationContext impersonatedUser = newId.Impersonate();

                    mRemoteIdentity = impersonatedUser;
                }
            }
            finally
            {
                // close handle(s)
                if (pExistingTokenHandle != IntPtr.Zero)
                    CloseHandle(pExistingTokenHandle);
                if (pDuplicateTokenHandle != IntPtr.Zero)
                    CloseHandle(pDuplicateTokenHandle);
            }

        }

        private void EndImpersonation()
        {
            if (mRemoteIdentity != null)
            {
                Logger.Debug("Ending impersonation");
                mRemoteIdentity.Undo();
            }
        }

        private ManagementScope ConnectWmiScope(string Namespace, bool Reconnect = false)
        {
            if (wmiConnections.ContainsKey(Namespace.ToLower()) && !Reconnect)
                return wmiConnections[Namespace.ToLower()];

            ManagementPath path = null;
            ManagementScope scope = null;

            if (mClientHostname == "localhost")
            {
                Logger.Debug("Connecting to WMI scope '" + Namespace + "' on localhost");
                path = new ManagementPath(Namespace);
                scope = new ManagementScope(path);
            }
            else
            {
                if (mClientUsername != null)
                {
                    Logger.Debug("Connecting to WMI scope '" + Namespace + "' on " + mClientHostname + " as " + mClientUsername + ":" + mClientPassword);
                    ConnectionOptions conn_options = new ConnectionOptions();
                    conn_options.Username = mClientUsername;
                    conn_options.Password = mClientPassword;
                    path = new ManagementPath(@"\\" + mClientHostname + "\\" + Namespace);
                    scope = new ManagementScope(path, conn_options);
                }
                else
                {
                    Logger.Debug("Connecting to WMI scope '" + Namespace + "' on " + mClientHostname + " as current user");
                    path = new ManagementPath(@"\\" + mClientHostname + "\\" + Namespace);
                    scope = new ManagementScope(path);
                }
            }
            try
            {
                scope.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                throw new InitiatorException("Invalid username/password", e);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
            catch (COMException e)
            {
                throw ComExceptionToInitiatorException(e);
            }

            if (wmiConnections.ContainsKey(Namespace.ToLower()))
                wmiConnections[Namespace.ToLower()] = scope;
            else
                wmiConnections.Add(Namespace.ToLower(), scope);

            return scope;
        }

        private Service ConnectVdsService(bool Reconnect = false)
        {
            if (mVdsService == null || Reconnect)
            {
                if (mClientHostname != "localhost" && mClientUsername != null)
                {
                    Logger.Debug("Connecting to VDS service on " + mClientHostname + " as " + mClientUsername + ":" + mClientPassword);
                    StartImpersonation();
                }
                else
                {
                    Logger.Debug("Connecting to VDS service on " + mClientHostname + " as current user");
                }
                try
                {
                    Service vds_service = new Microsoft.Storage.Vds.ServiceLoader().LoadService(mClientHostname);
                    vds_service.WaitForServiceReady();
                    //Logger.Debug("Scanning for disks...");
                    //vds_service.Reenumerate();
                    //vds_service.Refresh();
                    Logger.Debug("Cleaning mount points...");
                    vds_service.CleanupObsoleteMountPoints();
                    mVdsService = vds_service;
                }
                finally
                {
                    if (mClientHostname != "localhost" && mClientUsername != null)
                    {
                        EndImpersonation();
                    }
                }
            }
            mVdsService.AutoMount = false;
            return mVdsService;
        }

        /// <summary>
        /// Re-enumerate and refresh all attached disks
        /// </summary>
        public void RescanDisks()
        {
            Service vds = ConnectVdsService();
            Logger.Debug("Scanning for disks...");
            vds.Reenumerate();
            vds.Refresh();
        }

        private SoftwareProvider ConnectVdsProviderDynamic()
        {
            Service vds_service = ConnectVdsService();
            if (mClientHostname != "localhost" && mClientUsername != null)
            {
                Logger.Debug("Connecting to dynamic disk VDS provider on " + mClientHostname + " as " + mClientUsername + ":" + mClientPassword);
                StartImpersonation();
            }
            else
            {
                Logger.Debug("Connecting to dynamic disk VDS provider on " + mClientHostname + " as current user");
            }

            SoftwareProvider dynamic_disk_provider = null;
            try
            {
                Guid basic_guid = new Guid("{a86ae501-ef73-4c8d-827e-98ba5046b05f}"); // Only for managing DYNAMIC disks, not basic

                // Find the basic disk provider
                vds_service.HardwareProvider = false;
                vds_service.SoftwareProvider = true;
                foreach (SoftwareProvider provider in vds_service.Providers)
                {
                    if (provider.Id == basic_guid)
                    {
                        dynamic_disk_provider = provider;
                    }
                }
                if (dynamic_disk_provider == null)
                {
                    throw new InitiatorException("Could not find dynamic disk provider");
                }
            }
            finally
            {
                if (mClientHostname != "localhost" && mClientUsername != null)
                {
                    EndImpersonation();
                }
            }
            dynamic_disk_provider.Refresh();
            return dynamic_disk_provider;
        }

        private SoftwareProvider ConnectVdsProviderBasic()
        {
            Service vds_service = ConnectVdsService();
            if (mClientHostname != "localhost" && mClientUsername != null)
            {
                Logger.Debug("Connecting to basic disk VDS provider on " + mClientHostname + " as " + mClientUsername + ":" + mClientPassword);
                StartImpersonation();
            }
            else
            {
                Logger.Debug("Connecting to basic disk VDS provider on " + mClientHostname + " as current user");
            }

            SoftwareProvider basic_disk_provider = null;
            try
            {
                Guid basic_guid = new Guid("{ca7de14f-5bc8-48fd-93de-a19527b0459e}"); // Only for managing BASIC disks, not dynamic

                // Find the basic disk provider
                vds_service.HardwareProvider = false;
                vds_service.SoftwareProvider = true;
                foreach (SoftwareProvider provider in vds_service.Providers)
                {
                    if (provider.Id == basic_guid)
                    {
                        basic_disk_provider = provider;
                    }
                }
                if (basic_disk_provider == null)
                {
                    throw new InitiatorException("Could not find basic disk provider");
                }
            }
            finally
            {
                if (mClientHostname != "localhost" && mClientUsername != null)
                {
                    EndImpersonation();
                }
            }
            basic_disk_provider.Refresh();
            return basic_disk_provider;
        }
        
        #endregion

        #region Exceptions/Errors and InfoTypes
        public class InitiatorException : Exception
        {
            public UInt32 ErrorCode { get; set; }

            public InitiatorException(string message) : base(message) { }
            public InitiatorException(string message, UInt32 pErrorCode)
                : base(message)
            {
                this.ErrorCode = pErrorCode;
            }
            public InitiatorException(string message, Exception inner) : base(message, inner) { }
            public InitiatorException(string message, UInt32 pErrorCode, Exception inner)
                : base(message, inner)
            {
                this.ErrorCode = pErrorCode;
            }
            public InitiatorException(string message, UInt32? pErrorCode, Exception inner)
                : base(message, inner)
            {
                if (pErrorCode != null)
                    this.ErrorCode = (UInt32)pErrorCode;
            }
        }

        private class ProcessResult
        {
            public string Stdout;
            public string Stderr;
            public int ExitCode;
        }

        public class IscsiPortalInfo
        {
            // from MSiSCSIInitiator_SendTargetsPortalClass, MSiSCSIInitiator_TargetLoginOptions
            public string PortalAddress { get; set; }
            public UInt16 PortalPort { get; set; }
            public string AuthType { get; set; }
            public string Username { get; set; }

            public override string ToString()
            {
                return "PortalAddress: " + this.PortalAddress + ", PortalPort: " + this.PortalPort + ", AuthType: " + this.AuthType + ", Username: " + this.Username;
            }
        }
        
        public class IscsiTargetInfo
        {
            // from MSiSCSIInitiator_TargetClass, MSiSCSIInitiator_TargetLoginOptions
            public string DiscoveryMechanism { get; set; }
            public string InitiatorName { get; set; }
            public string TargetPortal { get; set; }
            public string TargetIqn { get; set; }
            public UInt32 TargetFlags { get; set; }
            public bool IsLoggedIn { get; set; }

            // the login options structure appears to not be initialized for targets - it is only used during login
            //public string AuthType { get; set; }
            //public string Username { get; set; }
        }

        public class IscsiSessionInfo
        {
            public string SessionId { get; set; }
            public string InitiatorIqn { get; set; }
            public string TargetIqn { get; set; }
            public string InitiatorAddress { get; set; }
            public UInt16 InitiatorPort { get; set; }
            public string TargetAddress { get; set; }
            public UInt16 TargetPort { get; set; }
            public string LegacyDeviceName { get; set; }
            public UInt32 DeviceNumber { get; set; }
        }

        public enum TargetType
        {
            iSCSI,
            FibreChannel
        }

        public enum IscsiTargetLoginState
        {
            LoggedIn,
            LoggedOut,
            Any
        }

        public class DiskInfoSimple
        {
            public string IscsiTargetName { get; set; }
            public string IscsiPortalAddress { get; set; }
            public UInt32 DeviceNumber { get; set; }
            public string LegacyDeviceName { get; set; }
            public string MountPoint { get; set; }
            public UInt32 SectorSize { get; set; }
            public UInt64 Size { get; set; }
            public bool Online { get; set; }
            public bool Readonly { get; set; }
            public string TargetType { get; set; }
            public string EUISerialNumber { get; set; }

            // SolidFire specific info
            public string SolidfireClusterID { get; set; }
            public int SolidfireVolumeID { get; set; }

            public UInt32 Lun { get; set; }

            public DiskInfoSimple()
            {
            }

            public DiskInfoSimple(DiskInfoSimple source)
            {
                this.IscsiTargetName = source.IscsiTargetName;
                this.IscsiPortalAddress = source.IscsiPortalAddress;
                this.DeviceNumber = source.DeviceNumber;
                this.LegacyDeviceName = source.LegacyDeviceName;
                this.MountPoint = source.MountPoint;
                this.SectorSize = source.SectorSize;
                this.Size = source.Size;
                this.Online = source.Online;
                this.Readonly = source.Readonly;
                this.TargetType = source.TargetType;
                this.EUISerialNumber = source.EUISerialNumber;

                this.SolidfireClusterID = source.SolidfireClusterID;
                this.SolidfireVolumeID = source.SolidfireVolumeID;

                this.Lun = source.Lun;
            }
        }

        public class DiskInfoDetailed : DiskInfoSimple
        {
            public string DevicePath { get; set; }
            public UInt32 Port { get; set; }
            public UInt32 Path { get; set; }
            public UInt32 Target { get; set; }
            public string EUISerialNumber { get; set; }
            public string ClusterID { get; set; }

            public DiskInfoDetailed()
            {
            }

            public DiskInfoDetailed(DiskInfoDetailed source) : base((DiskInfoSimple)source)
            {
                this.DevicePath = source.DevicePath;
                this.Path = source.Path;
                this.Port = source.Port;
                this.Target = source.Target;
                this.EUISerialNumber = source.EUISerialNumber;
                this.ClusterID = source.ClusterID;
            }
        }

        public class MpioDiskInfoSimple : DiskInfoSimple
        {
            // Additional info from VDS AdvancedDisk, DSM_QueryLBPolicy_V2, DSM_Load_Balance_Policy_V2, DSM_QuerySupportedLBPolicies_V2
            public string LoadBalancePolicy { get; set; }
            public int FailedPathCount { get; set; }
            public List<MpioPathInfoSimple> DSM_Paths { get; set; }

            public MpioDiskInfoSimple()
            {
                this.DSM_Paths = new List<MpioPathInfoSimple>();
            }

            public MpioDiskInfoSimple(DiskInfoSimple s) : base(s)
            {
                this.DSM_Paths = new List<MpioPathInfoSimple>();
            }

            public MpioDiskInfoSimple(MpioDiskInfoDetailed detail) : base(detail)
            {
                this.LoadBalancePolicy = detail.LoadBalancePolicy;
                this.FailedPathCount = detail.FailedPathCount;
                this.DSM_Paths = detail.DSM_Paths.ConvertAll(x => new MpioPathInfoSimple(x));
            }
        }

        public class MpioDiskInfoDetailed : DiskInfoDetailed
        {
            // Additional info from VDS AdvancedDisk, DSM_QueryLBPolicy_V2, DSM_Load_Balance_Policy_V2, DSM_QuerySupportedLBPolicies_V2
            public string LoadBalancePolicy { get; set; }
            public int FailedPathCount { get; set; }
            public List<MpioPathInfoDetailed> DSM_Paths { get; set; }
            public string InstanceName { get; set; }
            public string DeviceName { get; set; }
            public List<string> Supported_LB_Policies { get; set; }

            public MpioDiskInfoDetailed()
            {
                this.DSM_Paths = new List<MpioPathInfoDetailed>();
                this.Supported_LB_Policies = new List<string>();
            }

            public MpioDiskInfoDetailed(DiskInfoDetailed d) : base(d)
            {
                this.DSM_Paths = new List<MpioPathInfoDetailed>();
                Supported_LB_Policies = new List<string>();
            }
        }

        public class MpioPathInfoSimple
        {
            // Info from MPIO_DSM_Path_V2, PDOSCSI_ADDR
            public UInt64 DsmPathId { get; set; }
            public UInt32 FailedPath { get; set; }
            public int Lun { get; set; }
            public int PortNumber { get; set; }
            public int ScsiPathId { get; set; }
            public int TargetId { get; set; }

            public MpioPathInfoSimple()
            {
                Lun = -1;
                PortNumber = -1;
                ScsiPathId = -1;
                TargetId = -1;
            }

            public MpioPathInfoSimple(MpioPathInfoDetailed detail)
            {
                this.DsmPathId = detail.DsmPathId;
                this.FailedPath = detail.FailedPath;
                this.Lun = detail.Lun;
                this.PortNumber = detail.PortNumber;
                this.ScsiPathId = detail.ScsiPathId;
                this.TargetId = detail.TargetId;
            }
        }

        public class MpioPathInfoDetailed : MpioPathInfoSimple
        {
            // Info from MPIO_DSM_Path_V2, PDOSCSI_ADDR
            public UInt32 ALUASupport { get; set; }
            public UInt32 OptimizedPath { get; set; }
            public UInt32 PathWeight { get; set; }
            public UInt32 PreferredPath { get; set; }
            public UInt32 PrimaryPath { get; set; }
            public UInt64 Reserved { get; set; }
            public bool SymmetricLUA { get; set; }
            public UInt16 TargetPortGroup_Identifier { get; set; }
            public bool TargetPortGroup_Preferred { get; set; }
            public string TargetPortGroup_State { get; set; }

            public MpioPathInfoDetailed() : base()
            {
            }
        }

        public class FcHbaInfo
        {
            public string WWPN { get; set; }
            public string Speed { get; set; }
            public string PortState { get; set; }
            public string DriverVersion { get; set; }
            public string FirmwareVersion { get; set; }
            public string Model { get; set; }
            public string Description { get; set; }
            public List<string> TargetWWPNs { get; set; }
            public int UniqueLunCount { get; set; }
            public int TotalLunPathCount { get; set; }

            public FcHbaInfo()
            {
                TargetWWPNs = new List<string>();
            }
        }

        // From mpiodisk.h in the Windows Driver DDK
        public enum TargetPortGroup_State : uint
        {
            [Description("Active/Optimized")]
            STATE_ACTIVE_OPTIMIZED = 0,
            [Description("Active/Unoptimized")]
            STATE_ACTIVE_UNOPTIMIZED = 1,
            [Description("Standby")]
            STATE_STANDBY = 2,
            [Description("Unavailable")]
            STATE_UNAVAILABLE = 3,
            [Description("Not used")]
            STATE_NOT_USED = 16,
        }

        // From iscsidef.h in the Windows SDK
        public enum ISCSI_AUTH_TYPES : uint
        {
            [Description("None")]
            ISCSI_NO_AUTH_TYPE = 0, // IQN authentication
            [Description("CHAP")]
            ISCSI_CHAP_AUTH_TYPE = 1, // One-way CHAP authentication
            [Description("Mutual CHAP")]
            ISCSI_MUTUAL_CHAP_AUTH_TYPE = 2, // Two-way CHAP authentication
        }
        
        // From iscsierr.h in the Windows SDK
        public enum ISCSI_ERROR_CODES : uint
        {
            ISDSC_NON_SPECIFIC_ERROR = 0xEFFF0001,
            ISDSC_LOGIN_FAILED = 0xEFFF0002,
            ISDSC_CONNECTION_FAILED = 0xEFFF0003,
            ISDSC_INITIATOR_NODE_ALREADY_EXISTS = 0xEFFF0004,
            ISDSC_INITIATOR_NODE_NOT_FOUND = 0xEFFF0005,
            ISDSC_TARGET_MOVED_TEMPORARILY = 0xEFFF0006,
            ISDSC_TARGET_MOVED_PERMANENTLY = 0xEFFF0007,
            ISDSC_INITIATOR_ERROR = 0xEFFF0008,
            ISDSC_AUTHENTICATION_FAILURE = 0xEFFF0009,
            ISDSC_AUTHORIZATION_FAILURE = 0xEFFF000A,
            ISDSC_NOT_FOUND = 0xEFFF000B,
            ISDSC_TARGET_REMOVED = 0xEFFF000C,
            ISDSC_UNSUPPORTED_VERSION = 0xEFFF000D,
            ISDSC_TOO_MANY_CONNECTIONS = 0xEFFF000E,
            ISDSC_MISSING_PARAMETER = 0xEFFF000F,
            ISDSC_CANT_INCLUDE_IN_SESSION = 0xEFFF0010,
            ISDSC_SESSION_TYPE_NOT_SUPPORTED = 0xEFFF0011,
            ISDSC_TARGET_ERROR = 0xEFFF0012,
            ISDSC_SERVICE_UNAVAILABLE = 0xEFFF0013,
            ISDSC_OUT_OF_RESOURCES = 0xEFFF0014,
            ISDSC_CONNECTION_ALREADY_EXISTS = 0xEFFF0015,
            ISDSC_SESSION_ALREADY_EXISTS = 0xEFFF0016,
            ISDSC_INITIATOR_INSTANCE_NOT_FOUND = 0xEFFF0017,
            ISDSC_TARGET_ALREADY_EXISTS = 0xEFFF0018,
            ISDSC_DRIVER_BUG = 0xEFFF0019,
            ISDSC_INVALID_TEXT_KEY = 0xEFFF001A,
            ISDSC_INVALID_SENDTARGETS_TEXT = 0xEFFF001B,
            ISDSC_INVALID_SESSION_ID = 0xEFFF001C,
            ISDSC_SCSI_REQUEST_FAILED = 0xEFFF001D,
            ISDSC_TOO_MANY_SESSIONS = 0xEFFF001E,
            ISDSC_SESSION_BUSY = 0xEFFF001F,
            ISDSC_TARGET_MAPPING_UNAVAILABLE = 0xEFFF0020,
            ISDSC_ADDRESS_TYPE_NOT_SUPPORTED = 0xEFFF0021,
            ISDSC_LOGON_FAILED = 0xEFFF0022,
            ISDSC_SEND_FAILED = 0xEFFF0023,
            ISDSC_TRANSPORT_ERROR = 0xEFFF0024,
            ISDSC_VERSION_MISMATCH = 0xEFFF0025,
            ISDSC_TARGET_MAPPING_OUT_OF_RANGE = 0xEFFF0026,
            ISDSC_TARGET_PRESHAREDKEY_UNAVAILABLE = 0xEFFF0027,
            ISDSC_TARGET_AUTHINFO_UNAVAILABLE = 0xEFFF0028,
            ISDSC_TARGET_NOT_FOUND = 0xEFFF0029,
            ISDSC_LOGIN_USER_INFO_BAD = 0xEFFF002A,
            ISDSC_TARGET_MAPPING_EXISTS = 0xEFFF002B,
            ISDSC_HBA_SECURITY_CACHE_FULL = 0xEFFF002C,
            ISDSC_INVALID_PORT_NUMBER = 0xEFFF002D,
            ISDSC_OPERATION_NOT_ALL_SUCCESS = 0xAFFF002E,
            ISDSC_HBA_SECURITY_CACHE_NOT_SUPPORTED = 0xEFFF002F,
            ISDSC_IKE_ID_PAYLOAD_TYPE_NOT_SUPPORTED = 0xEFFF0030,
            ISDSC_IKE_ID_PAYLOAD_INCORRECT_SIZE = 0xEFFF0031,
            ISDSC_TARGET_PORTAL_ALREADY_EXISTS = 0xEFFF0032,
            ISDSC_TARGET_ADDRESS_ALREADY_EXISTS = 0xEFFF0033,
            ISDSC_NO_AUTH_INFO_AVAILABLE = 0xEFFF0034,
            ISDSC_NO_TUNNEL_OUTER_MODE_ADDRESS = 0xEFFF0035,
            ISDSC_CACHE_CORRUPTED = 0xEFFF0036,
            ISDSC_REQUEST_NOT_SUPPORTED = 0xEFFF0037,
            ISDSC_TARGET_OUT_OF_RESORCES = 0xEFFF0038,
            ISDSC_SERVICE_DID_NOT_RESPOND = 0xEFFF0039,
            ISDSC_ISNS_SERVER_NOT_FOUND = 0xEFFF003A,
            ISDSC_OPERATION_REQUIRES_REBOOT = 0xAFFF003B,
            ISDSC_NO_PORTAL_SPECIFIED = 0xEFFF003C,
            ISDSC_CANT_REMOVE_LAST_CONNECTION = 0xEFFF003D,
            ISDSC_SERVICE_NOT_RUNNING = 0xEFFF003E,
            ISDSC_TARGET_ALREADY_LOGGED_IN = 0xEFFF003F,
            ISDSC_DEVICE_BUSY_ON_SESSION = 0xEFFF0040,
            ISDSC_COULD_NOT_SAVE_PERSISTENT_LOGIN_DATA = 0xEFFF0041,
            ISDSC_COULD_NOT_REMOVE_PERSISTENT_LOGIN_DATA = 0xEFFF0042,
            ISDSC_PORTAL_NOT_FOUND = 0xEFFF0043,
            ISDSC_INITIATOR_NOT_FOUND = 0xEFFF0044,
            ISDSC_DISCOVERY_MECHANISM_NOT_FOUND = 0xEFFF0045,
            ISDSC_IPSEC_NOT_SUPPORTED_ON_OS = 0xEFFF0046,
            ISDSC_PERSISTENT_LOGIN_TIMEOUT = 0xEFFF0047,
            ISDSC_SHORT_CHAP_SECRET = 0xAFFF0048,
            ISDSC_EVALUATION_PEROID_EXPIRED = 0xEFFF0049,
            ISDSC_INVALID_CHAP_SECRET = 0xEFFF004A,
            ISDSC_INVALID_TARGET_CHAP_SECRET = 0xEFFF004B,
            ISDSC_INVALID_INITIATOR_CHAP_SECRET = 0xEFFF004C,
            ISDSC_INVALID_CHAP_USER_NAME = 0xEFFF004D,
            ISDSC_INVALID_LOGON_AUTH_TYPE = 0xEFFF004E,
            ISDSC_INVALID_TARGET_MAPPING = 0xEFFF004F,
            ISDSC_INVALID_TARGET_ID = 0xEFFF0050,
            ISDSC_INVALID_ISCSI_NAME = 0xEFFF0051,
            ISDSC_INCOMPATIBLE_ISNS_VERSION = 0xEFFF0052,
            ISDSC_FAILED_TO_CONFIGURE_IPSEC = 0xEFFF0053,
            ISDSC_BUFFER_TOO_SMALL = 0xEFFF0054,
            ISDSC_INVALID_LOAD_BALANCE_POLICY = 0xEFFF0055,
            ISDSC_INVALID_PARAMETER = 0xEFFF0056,
            ISDSC_DUPLICATE_PATH_SPECIFIED = 0xEFFF0057,
            ISDSC_PATH_COUNT_MISMATCH = 0xEFFF0058,
            ISDSC_INVALID_PATH_ID = 0xEFFF0059,
            ISDSC_MULTIPLE_PRIMARY_PATHS_SPECIFIED = 0xEFFF005A,
            ISDSC_NO_PRIMARY_PATH_SPECIFIED = 0xEFFF005B,
            ISDSC_DEVICE_ALREADY_PERSISTENTLY_BOUND = 0xEFFF005C,
            ISDSC_DEVICE_NOT_FOUND = 0xEFFF005D,
            ISDSC_DEVICE_NOT_ISCSI_OR_PERSISTENT = 0xEFFF005E,
            ISDSC_DNS_NAME_UNRESOLVED = 0xEFFF005F,
            ISDSC_NO_CONNECTION_AVAILABLE = 0xEFFF0060,
            ISDSC_LB_POLICY_NOT_SUPPORTED = 0xEFFF0061,
            ISDSC_REMOVE_CONNECTION_IN_PROGRESS = 0xEFFF0062,
            ISDSC_INVALID_CONNECTION_ID = 0xEFFF0063,
            ISDSC_CANNOT_REMOVE_LEADING_CONNECTION = 0xEFFF0064,
            ISDSC_RESTRICTED_BY_GROUP_POLICY = 0xEFFF0065,
            ISDSC_ISNS_FIREWALL_BLOCKED = 0xEFFF0066,
            ISDSC_FAILURE_TO_PERSIST_LB_POLICY = 0xEFFF0067,
            ISDSC_INVALID_HOST = 0xEFFF0068,
        }

        // From vdserr.h in the Windows SDK
        public enum VDS_COM_ERROR_CODES : uint
        {
            VDS_E_NOT_SUPPORTED = 0x80042400,
            VDS_E_INITIALIZED_FAILED = 0x80042401,
            VDS_E_INITIALIZE_NOT_CALLED = 0x80042402,
            VDS_E_ALREADY_REGISTERED = 0x80042403,
            VDS_E_ANOTHER_CALL_IN_PROGRESS = 0x80042404,
            VDS_E_OBJECT_NOT_FOUND = 0x80042405,
            VDS_E_INVALID_SPACE = 0x80042406,
            VDS_E_PARTITION_LIMIT_REACHED = 0x80042407,
            VDS_E_PARTITION_NOT_EMPTY = 0x80042408,
            VDS_E_OPERATION_PENDING = 0x80042409,
            VDS_E_OPERATION_DENIED = 0x8004240A,
            VDS_E_OBJECT_DELETED = 0x8004240B,
            VDS_E_CANCEL_TOO_LATE = 0x8004240C,
            VDS_E_OPERATION_CANCELED = 0x8004240D,
            VDS_E_CANNOT_EXTEND = 0x8004240E,
            VDS_E_NOT_ENOUGH_SPACE = 0x8004240F,
            VDS_E_NOT_ENOUGH_DRIVE = 0x80042410,
            VDS_E_BAD_COOKIE = 0x80042411,
            VDS_E_NO_MEDIA = 0x80042412,
            VDS_E_DEVICE_IN_USE = 0x80042413,
            VDS_E_INVALID_OPERATION = 0x80042415,
            VDS_E_PATH_NOT_FOUND = 0x80042416,
            VDS_E_DISK_NOT_INITIALIZED = 0x80042417,
            VDS_E_NOT_AN_UNALLOCATED_DISK = 0x80042418,
            VDS_E_UNRECOVERABLE_ERROR = 0x80042419,
            VDS_S_DISK_PARTIALLY_CLEANED = 0x0004241A,
            VDS_E_OBJECT_EXISTS = 0x8004241D,
            VDS_E_PROVIDER_CACHE_CORRUPT = 0x8004241F,
            VDS_E_DMADMIN_METHOD_CALL_FAILED = 0x80042420,
            VDS_S_PROVIDER_ERROR_LOADING_CACHE = 0x00042421,
            VDS_E_PROVIDER_VOL_DEVICE_NAME_NOT_FOUND = 0x80042422,
            VDS_E_DMADMIN_CORRUPT_NOTIFICATION = 0x80042424,
            VDS_E_INCOMPATIBLE_FILE_SYSTEM = 0x80042425,
            VDS_E_INCOMPATIBLE_MEDIA = 0x80042426,
            VDS_E_ACCESS_DENIED = 0x80042427,
            VDS_E_MEDIA_WRITE_PROTECTED = 0x80042428,
            VDS_E_BAD_LABEL = 0x80042429,
            VDS_E_CANT_QUICK_FORMAT = 0x8004242A,
            VDS_E_IO_ERROR = 0x8004242B,
            VDS_E_VOLUME_TOO_SMALL = 0x8004242C,
            VDS_E_VOLUME_TOO_BIG = 0x8004242D,
            VDS_E_CLUSTER_SIZE_TOO_SMALL = 0x8004242E,
            VDS_E_CLUSTER_SIZE_TOO_BIG = 0x8004242F,
            VDS_E_CLUSTER_COUNT_BEYOND_32BITS = 0x80042430,
            VDS_E_OBJECT_STATUS_FAILED = 0x80042431,
            VDS_E_VOLUME_INCOMPLETE = 0x80042432,
            VDS_E_EXTENT_SIZE_LESS_THAN_MIN = 0x80042433,
            VDS_S_UPDATE_BOOTFILE_FAILED = 0x00042434,
            VDS_S_BOOT_PARTITION_NUMBER_CHANGE = 0x00042436,
            VDS_E_NO_FREE_SPACE = 0x80042437,
            VDS_E_ACTIVE_PARTITION = 0x80042438,
            VDS_E_PARTITION_OF_UNKNOWN_TYPE = 0x80042439,
            VDS_E_LEGACY_VOLUME_FORMAT = 0x8004243A,
            VDS_E_NON_CONTIGUOUS_DATA_PARTITIONS = 0x8004243B,
            VDS_E_MIGRATE_OPEN_VOLUME = 0x8004243C,
            VDS_E_VOLUME_NOT_ONLINE = 0x8004243D,
            VDS_E_VOLUME_NOT_HEALTHY = 0x8004243E,
            VDS_E_VOLUME_SPANS_DISKS = 0x8004243F,
            VDS_E_REQUIRES_CONTIGUOUS_DISK_SPACE = 0x80042440,
            VDS_E_BAD_PROVIDER_DATA = 0x80042441,
            VDS_E_PROVIDER_FAILURE = 0x80042442,
            VDS_S_VOLUME_COMPRESS_FAILED = 0x00042443,
            VDS_E_PACK_OFFLINE = 0x80042444,
            VDS_E_VOLUME_NOT_A_MIRROR = 0x80042445,
            VDS_E_NO_EXTENTS_FOR_VOLUME = 0x80042446,
            VDS_E_DISK_NOT_LOADED_TO_CACHE = 0x80042447,
            VDS_E_INTERNAL_ERROR = 0x80042448,
            VDS_E_DISK_NOT_ONLINE = 0x8004244B,
            VDS_E_DISK_IN_USE_BY_VOLUME = 0x8004244C,
            VDS_E_VOLUME_NOT_MOUNTED = 0x8004244F,
            VDS_E_IMPORT_SET_INCOMPLETE = 0x80042451,
            VDS_E_OBJECT_OUT_OF_SYNC = 0x80042453,
            VDS_E_MISSING_DISK = 0x80042454,
            VDS_E_DISK_PNP_REG_CORRUPT = 0x80042455,
            VDS_E_LBN_REMAP_ENABLED_FLAG = 0x80042456,
            VDS_E_NO_DRIVELETTER_FLAG = 0x80042457,
            VDS_E_REVERT_ON_CLOSE = 0x80042458,
            VDS_E_REVERT_ON_CLOSE_SET = 0x80042459,
            VDS_S_UNABLE_TO_GET_GPT_ATTRIBUTES = 0x0004245B,
            VDS_E_VOLUME_TEMPORARILY_DISMOUNTED = 0x8004245C,
            VDS_E_VOLUME_PERMANENTLY_DISMOUNTED = 0x8004245D,
            VDS_E_VOLUME_HAS_PATH = 0x8004245E,
            VDS_E_REPAIR_VOLUMESTATE = 0x80042460,
            VDS_E_LDM_TIMEOUT = 0x80042461,
            VDS_E_REVERT_ON_CLOSE_MISMATCH = 0x80042462,
            VDS_E_RETRY = 0x80042463,
            VDS_E_ONLINE_PACK_EXISTS = 0x80042464,
            VDS_S_GPT_BOOT_MIRRORED_TO_MBR = 0x80042469,
            VDS_E_NO_VOLUME_LAYOUT = 0x80042502,
            VDS_E_CORRUPT_VOLUME_INFO = 0x80042503,
            VDS_E_DRIVER_INTERNAL_ERROR = 0x80042505,
            VDS_E_VOLUME_INVALID_NAME = 0x80042507,
            VDS_E_CORRUPT_PARTITION_INFO = 0x80042509,
            VDS_E_CORRUPT_EXTENT_INFO = 0x8004250B,
            VDS_E_PROVIDER_EXITING = 0x80042514,
            VDS_E_EXTENT_EXCEEDS_DISK_FREE_SPACE = 0x80042515,
            VDS_E_MEMBER_SIZE_INVALID = 0x80042516,
            VDS_S_NO_NOTIFICATION = 0x80042517,
            VDS_E_INVALID_DISK = 0x80042519,
            VDS_E_INVALID_PACK = 0x8004251A,
            VDS_E_CANNOT_SHRINK = 0x8004251E,
            VDS_E_INVALID_PLEX_COUNT = 0x80042521,
            VDS_E_INVALID_MEMBER_COUNT = 0x80042522,
            VDS_E_INVALID_PLEX_ORDER = 0x80042523,
            VDS_E_INVALID_MEMBER_ORDER = 0x80042524,
            VDS_E_INVALID_STRIPE_SIZE = 0x80042525,
            VDS_E_INVALID_DISK_COUNT = 0x80042526,
            VDS_E_VOLUME_DISK_COUNT_MAX_EXCEEDED = 0x80042529,
            VDS_E_DISK_NOT_FOUND_IN_PACK = 0x8004252D,
            VDS_E_ONE_EXTENT_PER_DISK = 0x80042531,
            VDS_E_DISK_REMOVEABLE = 0x8004255A,
            VDS_E_INVALID_DRIVE_LETTER = 0x8004255E,
            VDS_E_INVALID_DRIVE_LETTER_COUNT = 0x8004255F,
            VDS_E_INVALID_FS_FLAG = 0x80042560,
            VDS_E_INVALID_FS_TYPE = 0x80042561,
            VDS_E_INVALID_OBJECT_TYPE = 0x80042562,
            VDS_E_INVALID_PARTITION_TYPE = 0x80042565,
            VDS_E_PARTITION_NOT_OEM = 0x8004256F,
            VDS_E_PARTITION_STYLE_MISMATCH = 0x80042571,
            VDS_E_SHRINK_SIZE_LESS_THAN_MIN = 0x80042573,
            VDS_E_SHRINK_SIZE_TOO_BIG = 0x80042574,
            VDS_E_VOLUME_SIMPLE_SPANNED = 0x80042589,
            VDS_E_PARTITION_MSR = 0x8004258C,
            VDS_E_PARTITION_LDM = 0x8004258D,
            VDS_E_ALIGN_NOT_A_POWER_OF_TWO = 0x8004258F,
            VDS_E_ALIGN_IS_ZERO = 0x80042590,
            VDS_E_CANT_INVALIDATE_FVE = 0x80042592,
            VDS_E_FS_NOT_DETERMINED = 0x80042593,
            VDS_E_FAILED_TO_ONLINE_DISK = 0x80042596,
            VDS_E_FAILED_TO_OFFLINE_DISK = 0x80042597,
            VDS_S_NAME_TRUNCATED = 0x00042700,
            VDS_E_NAME_NOT_UNIQUE = 0x80042701,
            VDS_S_STATUSES_INCOMPLETELY_SET = 0x00042702,
            VDS_E_TARGET_SPECIFIC_NOT_SUPPORTED = 0x80042706,
            VDS_E_INITIATOR_SPECIFIC_NOT_SUPPORTED = 0x80042707,
            VDS_E_ISCSI_LOGIN_FAILED = 0x80042708,
            VDS_E_ISCSI_LOGOUT_FAILED = 0x80042709,
            VDS_E_ISCSI_SESSION_NOT_FOUND = 0x8004270A,
            VDS_E_ASSOCIATED_LUNS_EXIST = 0x8004270B,
            VDS_E_ASSOCIATED_PORTALS_EXIST = 0x8004270C,
            VDS_E_NO_DISK_PATHNAME = 0x8004270F,
            VDS_E_ISCSI_LOGOUT_INCOMPLETE = 0x80042710,
            VDS_E_NO_VOLUME_PATHNAME = 0x80042711,
            VDS_E_PROVIDER_CACHE_OUTOFSYNC = 0x80042712,
            VDS_E_NO_IMPORT_TARGET = 0x80042713,
            VDS_S_ALREADY_EXISTS = 0x00042714,
            VDS_S_PROPERTIES_INCOMPLETE = 0x00042715,
            VDS_S_ISCSI_SESSION_NOT_FOUND_PERSISTENT_LOGIN_REMOVED = 0x00042800,
            VDS_S_ISCSI_PERSISTENT_LOGIN_MAY_NOT_BE_REMOVED = 0x00042801,
            VDS_S_ISCSI_LOGIN_ALREAD_EXISTS = 0x00042802,
            VDS_E_UNABLE_TO_FIND_BOOT_DISK = 0x80042803,
            VDS_E_INCORRECT_BOOT_VOLUME_EXTENT_INFO = 0x80042804,
            VDS_E_GET_SAN_POLICY = 0x80042805,
            VDS_E_SET_SAN_POLICY = 0x80042806,
            VDS_E_BOOT_DISK = 0x80042807,
            VDS_S_DISK_MOUNT_FAILED = 0x00042808,
            VDS_S_DISK_DISMOUNT_FAILED = 0x00042809,
            VDS_E_DISK_IS_OFFLINE = 0x8004280A,
            VDS_E_DISK_IS_READ_ONLY = 0x8004280B,
            VDS_E_PAGEFILE_DISK = 0x8004280C,
            VDS_E_HIBERNATION_FILE_DISK = 0x8004280D,
            VDS_E_CRASHDUMP_DISK = 0x8004280E,
            VDS_E_UNABLE_TO_FIND_SYSTEM_DISK = 0x8004280F,
            VDS_E_INCORRECT_SYSTEM_VOLUME_EXTENT_INFO = 0x80042810,
            VDS_E_SYSTEM_DISK = 0x80042811,
            VDS_E_VOLUME_SHRINK_FVE_LOCKED = 0x80042812,
            VDS_E_VOLUME_SHRINK_FVE_CORRUPT = 0x80042813,
            VDS_E_VOLUME_SHRINK_FVE_RECOVERY = 0x80042814,
            VDS_E_VOLUME_SHRINK_FVE = 0x80042815,
            VDS_E_SHRINK_OVER_DATA = 0x80042816,
            VDS_E_INVALID_SHRINK_SIZE = 0x80042817,
            VDS_E_LUN_DISK_MISSING = 0x80042818,
            VDS_E_LUN_DISK_FAILED = 0x80042819,
            VDS_E_LUN_DISK_NOT_READY = 0x8004281A,
            VDS_E_LUN_DISK_NO_MEDIA = 0x8004281B,
            VDS_E_LUN_NOT_READY = 0x8004281C,
            VDS_E_LUN_OFFLINE = 0x8004281D,
            VDS_E_LUN_FAILED = 0x8004281E,
            VDS_E_VOLUME_EXTEND_FVE_LOCKED = 0x8004281F,
            VDS_E_VOLUME_EXTEND_FVE_CORRUPT = 0x80042820,
            VDS_E_VOLUME_EXTEND_FVE_RECOVERY = 0x80042821,
            VDS_E_VOLUME_EXTEND_FVE = 0x80042822,
            VDS_E_SECTOR_SIZE_ERROR = 0x80042823,
            VDS_E_INITIATOR_ADAPTER_NOT_FOUND = 0x80042900,
            VDS_E_TARGET_PORTAL_NOT_FOUND = 0x80042901,
            VDS_E_INVALID_PORT_PATH = 0x80042902,
            VDS_E_INVALID_ISCSI_TARGET_NAME = 0x80042903,
            VDS_E_SET_TUNNEL_MODE_OUTER_ADDRESS = 0x80042904,
            VDS_E_ISCSI_GET_IKE_INFO = 0x80042905,
            VDS_E_ISCSI_SET_IKE_INFO = 0x80042906,
            VDS_E_SUBSYSTEM_ID_IS_NULL = 0x80042907,
            VDS_E_ISCSI_INITIATOR_NODE_NAME = 0x80042908,
            VDS_E_ISCSI_GROUP_PRESHARE_KEY = 0x80042909,
            VDS_E_ISCSI_CHAP_SECRET = 0x8004290A,
            VDS_E_INVALID_IP_ADDRESS = 0x8004290B,
            VDS_E_REBOOT_REQUIRED = 0x8004290C,
            VDS_E_VOLUME_GUID_PATHNAME_NOT_ALLOWED = 0x8004290D,
            VDS_E_BOOT_PAGEFILE_DRIVE_LETTER = 0x8004290E,
            VDS_E_DELETE_WITH_CRITICAL = 0x8004290F,
            VDS_E_CLEAN_WITH_DATA = 0x80042910,
            VDS_E_CLEAN_WITH_OEM = 0x80042911,
            VDS_E_CLEAN_WITH_CRITICAL = 0x80042912,
            VDS_E_FORMAT_CRITICAL = 0x80042913,
            VDS_E_NTFS_FORMAT_NOT_SUPPORTED = 0x80042914,
            VDS_E_FAT32_FORMAT_NOT_SUPPORTED = 0x80042915,
            VDS_E_FAT_FORMAT_NOT_SUPPORTED = 0x80042916,
            VDS_E_FORMAT_NOT_SUPPORTED = 0x80042917,
            VDS_E_COMPRESSION_NOT_SUPPORTED = 0x80042918,
            VDS_E_VDISK_NOT_OPEN = 0x80042919,
            VDS_E_VDISK_INVALID_OP_STATE = 0x8004291A,
            VDS_E_INVALID_PATH = 0x8004291B,
            VDS_E_INVALID_ISCSI_PATH = 0x8004291C,
            VDS_E_SHRINK_LUN_NOT_UNMASKED = 0x8004291D,
            VDS_E_LUN_DISK_READ_ONLY = 0x8004291E,
            VDS_E_LUN_UPDATE_DISK = 0x8004291F,
            VDS_E_LUN_DYNAMIC = 0x80042920,
            VDS_E_LUN_DYNAMIC_OFFLINE = 0x80042921,
            VDS_E_LUN_SHRINK_GPT_HEADER = 0x80042922,
            VDS_E_MIRROR_NOT_SUPPORTED = 0x80042923,
            VDS_E_RAID5_NOT_SUPPORTED = 0x80042924,
            VDS_E_DISK_NOT_CONVERTIBLE_SIZE = 0x80042925,
            VDS_E_OFFLINE_NOT_SUPPORTED = 0x80042926,
            VDS_E_VDISK_PATHNAME_INVALID = 0x80042927,
            VDS_E_EXTEND_TOO_MANY_CLUSTERS = 0x80042928,
            VDS_E_EXTEND_UNKNOWN_FILESYSTEM = 0x80042929,
            VDS_E_SHRINK_UNKNOWN_FILESYSTEM = 0x8004292A,
            VDS_E_VD_DISK_NOT_OPEN = 0x8004292B,
            VDS_E_VD_DISK_IS_EXPANDING = 0x8004292C,
            VDS_E_VD_DISK_IS_COMPACTING = 0x8004292D,
            VDS_E_VD_DISK_IS_MERGING = 0x8004292E,
            VDS_E_VD_IS_ATTACHED = 0x8004292F,
            VDS_E_VD_DISK_ALREADY_OPEN = 0x80042930,
            VDS_E_VD_DISK_ALREADY_EXPANDING = 0x80042931,
            VDS_E_VD_ALREADY_COMPACTING = 0x80042932,
            VDS_E_VD_ALREADY_MERGING = 0x80042933,
            VDS_E_VD_ALREADY_ATTACHED = 0x80042934,
            VDS_E_VD_ALREADY_DETACHED = 0x80042935,
            VDS_E_VD_NOT_ATTACHED_READONLY = 0x80042936,
            VDS_E_VD_IS_BEING_ATTACHED = 0x80042937,
            VDS_E_VD_IS_BEING_DETACHED = 0x80042938,
        }

        // from hbaapi.h in the Windows Driver DDK
        public enum HBA_PORTSPEED : uint
        {
            [Description("Unknown")]
            HBA_PORTSPEED_UNKNOWN = 0,    /* Unknown - transceiver incapable of reporting */
            [Description("1Gb")]
            HBA_PORTSPEED_1GBIT = 1,    /* 1 GBit/sec */
            [Description("2Gb")]
            HBA_PORTSPEED_2GBIT = 2,    /* 2 GBit/sec */
            [Description("10Gb")]
            HBA_PORTSPEED_10GBIT = 4,    /* 10 GBit/sec */
            [Description("4Gb")]
            HBA_PORTSPEED_4GBIT = 8,    /* 4 GBit/sec */
            [Description("8Gb")]
            HBA_FCPHYSPEED_8GBIT = 16,    /* 8 GBit/sec */
            [Description("16Gb")]
            HBA_FCPHYSPEED_16GBIT = 32,    /* 16 GBit/sec */
            [Description("Not established")]
            HBA_PORTSPEED_NOT_NEGOTIATE = (1 << 15) /* Speed not established */
        }

        // from hbaapi.h in the Windows Driver DDK
        public enum HBA_PORTTYPE : uint
        {
            HBA_PORTTYPE_UNKNOWN = 1, /* Unknown */
            HBA_PORTTYPE_OTHER = 2, /* Other */
            HBA_PORTTYPE_NOTPRESENT = 3, /* Not present */
            HBA_PORTTYPE_NPORT = 5, /* Fabric */
            HBA_PORTTYPE_NLPORT = 6, /* Public Loop */
            HBA_PORTTYPE_FLPORT = 7, /* Fabric on a Loop */
            HBA_PORTTYPE_FPORT = 8, /* Fabric Port */
            HBA_PORTTYPE_EPORT = 9, /* Fabric expansion port */
            HBA_PORTTYPE_GPORT = 10, /* Generic Fabric Port */
            HBA_PORTTYPE_LPORT = 20, /* Private Loop */
            HBA_PORTTYPE_PTP = 21, /* Point to Point */
            HBA_PORTTYPE_SASDEVICE = 30, /* SAS (SSP or STP) */
            HBA_PORTTYPE_SATADEVICE = 31, /* SATA Device, i.e. Direct Attach SATA */
            HBA_PORTTYPE_SASEXPANDER = 32, /* SAS Expander */
        }

        // from hbaapi.h in the Windows Driver DDK
        public enum HBA_PORTSTATE : uint
        {
            [Description("Unknown")]
            HBA_PORTSTATE_UNKNOWN = 1, /* Unknown */
            [Description("Online")]
            HBA_PORTSTATE_ONLINE = 2, /* Operational */
            [Description("User Offline")]
            HBA_PORTSTATE_OFFLINE = 3, /* User Offline */
            [Description("Bypassed")]
            HBA_PORTSTATE_BYPASSED = 4, /* Bypassed */
            [Description("Diagnostics")]
            HBA_PORTSTATE_DIAGNOSTICS = 5, /* In diagnostics mode */
            [Description("Link down")]
            HBA_PORTSTATE_LINKDOWN = 6, /* Link Down */
            [Description("Error")]
            HBA_PORTSTATE_ERROR = 7, /* Port Error */
            [Description("Loopback")]
            HBA_PORTSTATE_LOOPBACK = 8, /* Loopback */
            [Description("Degraded")]
            HBA_PORTSTATE_DEGRADED = 9, /* Degraded, but Operational mode */
        }

        // from hbaapi.h in the Windows Driver DDK
        public enum HBA_STATUS : uint
        {
            HBA_STATUS_OK = 0,
            HBA_STATUS_ERROR = 1,   /* Error */
            HBA_STATUS_ERROR_NOT_SUPPORTED = 2,   /* Function not supported.*/
            HBA_STATUS_ERROR_INVALID_HANDLE = 3,   /* invalid handle */
            HBA_STATUS_ERROR_ARG = 4,   /* Bad argument */
            HBA_STATUS_ERROR_ILLEGAL_WWN = 5,   /* WWN not recognized */
            HBA_STATUS_ERROR_ILLEGAL_INDEX = 6,   /* Index not recognized */
            HBA_STATUS_ERROR_MORE_DATA = 7,   /* Larger buffer required */
            /* Information has changed since the last call to HBA_RefreshInformation */
            HBA_STATUS_ERROR_STALE_DATA = 8,
            /* SCSI Check Condition reported*/
            HBA_STATUS_SCSI_CHECK_CONDITION = 9,
            /* Adapter busy or reserved, retry may be effective*/
            HBA_STATUS_ERROR_BUSY = 10,
            /* Request timed out, retry may be effective */
            HBA_STATUS_ERROR_TRY_AGAIN = 11,
            /* Referenced HBA has been removed or deactivated */
            HBA_STATUS_ERROR_UNAVAILABLE = 12,
            /* The requested ELS was rejected  by the local adapter */
            HBA_STATUS_ERROR_ELS_REJECT = 13,
            /* The specified LUN is not provided  by the specified adapter */
            HBA_STATUS_ERROR_INVALID_LUN = 14,
            /* An incompatibility has been detected among the library and driver modules */
            /* invoked which will cause one or more functions in the highest version */
            /* that all support to operate incorrectly.  */
            /* The differing function sets of software modules implementing different */
            /* versions of the HBA API specification does not in itself constitute an */
            /* incompatibility. */
            /* Known interoperability bugs among supposedly compatible versions */
            /* should be reported as incompatibilities, */
            /* but not all such interoperability bugs may be known. */
            /* This value may be returned by any function which calls a */
            /* Vendor Specific Library,  and by HBA_LoadLibrary and HBA_GetAdapterName. */
            HBA_STATUS_ERROR_INCOMPATIBLE = 15,
            /* Multiple adapters have a matching WWN. */
            /* This could occur if the NodeWWN of multiple adapters is identical. */
            HBA_STATUS_ERROR_AMBIGUOUS_WWN = 16,
            /* A persistent binding request included a bad local SCSI bus number */
            HBA_STATUS_ERROR_LOCAL_BUS = 17,
            /* A persistent binding request included a bad local SCSI target number */
            HBA_STATUS_ERROR_LOCAL_TARGET = 18,
            /* A persistent binding request included a bad local SCSI logical unit number */
            HBA_STATUS_ERROR_LOCAL_LUN = 19,
            /* A persistent binding set request included */
            /* a local SCSI ID that was already bound */
            HBA_STATUS_ERROR_LOCAL_SCSIID_BOUND = 20,
            /* A persistent binding request included a bad or unlocatable FCP Target FCID */
            HBA_STATUS_ERROR_TARGET_FCID = 21,
            /* A persistent binding request included a bad FCP Target Node WWN */
            HBA_STATUS_ERROR_TARGET_NODE_WWN = 22,
            /* A persistent binding request included a bad FCP Target Port WWN */
            HBA_STATUS_ERROR_TARGET_PORT_WWN = 23,
            /* A persistent binding request included */
            /* an FCP Logical Unit Number not defined by the identified Target*/
            HBA_STATUS_ERROR_TARGET_LUN = 24,
            /* A persistent binding request included */
            /* an undefined or otherwise inaccessible Logical Unit Unique Identifier */
            HBA_STATUS_ERROR_TARGET_LUID = 25,
            /* A persistent binding remove request included */
            /* a binding which did not match a binding established by the specified port */
            HBA_STATUS_ERROR_NO_SUCH_BINDING = 26,
            /* A SCSI command was requested to an Nx_Port that was not a SCSI Target Port */
            HBA_STATUS_ERROR_NOT_A_TARGET = 27,
            /* A request was made concerning an unsupported FC-4 protocol */
            HBA_STATUS_ERROR_UNSUPPORTED_FC4 = 28,
            /* A request was made to enable unimplemented capabilities for a port */
            HBA_STATUS_ERROR_INCAPABLE = 29,
            /* A SCSI function was rejected to prevent causing */
            /* a SCSI overlapped command condition (see SAM-3) */
            HBA_STATUS_ERROR_TARGET_BUSY = 30,
            /* A call was made to HBA_FreeLibrary when no library was loaded */
            HBA_STATUS_ERROR_NOT_LOADED = 31,
            /* A call was made to HBA_LoadLibrary when a library was already loaded */
            HBA_STATUS_ERROR_ALREADY_LOADED = 32,
            /* The Address Identifier specified in a call to HBA_SendRNIDV2 */
            /* violates access control rules for that call */
            HBA_STATUS_ERROR_ILLEGAL_FCID = 33,
            HBA_STATUS_ERROR_NOT_ASCSIDEVICE = 34,
            HBA_STATUS_ERROR_INVALID_PROTOCOL_TYPE = 35,
            HBA_STATUS_ERROR_BAD_EVENT_TYPE = 36,
        }

        // from mpiodisk.h in the Windows Driver DDK
        public enum DSM_LB_POLICY : uint
        {
            [Description("Failover Only")]
            DSM_LB_FAILOVER = 1,
            [Description("Round Robin")]
            DSM_LB_ROUND_ROBIN = 2,
            [Description("Round Robin with Subset")]
            DSM_LB_ROUND_ROBIN_WITH_SUBSET = 3,
            [Description("Least Queue Depth")]
            DSM_LB_DYN_LEAST_QUEUE_DEPTH = 4,
            [Description("Weighted Paths")]
            DSM_LB_WEIGHTED_PATHS = 5,
            [Description("Least Blocks")]
            DSM_LB_LEAST_BLOCKS = 6,
            [Description("Vendor Specific")]
            DSM_LB_VENDOR_SPECIFIC = 7,
        }

        private static InitiatorException ManagementExceptionToInitiatorException(ManagementException e)
        {
            
            // Look for a status code
            if (e.ErrorInformation != null)
            {
                UInt32 error_code = 0;
                if (e.ErrorInformation.Properties["StatusCode"] != null)
                {
                    PropertyData status_property = e.ErrorInformation.Properties["StatusCode"];
                    if (status_property.Type == CimType.UInt32 && status_property.Value != null)
                    {
                        error_code = (UInt32)status_property.Value;

                        // See if there is any description available
                        string error_description = null;
                        if (e.ErrorInformation.Properties["Description"] != null)
                            error_description = e.ErrorInformation.Properties["Description"].Value as String;
                        if (!string.IsNullOrEmpty(error_description))
                        {
                            if (error_code == 1717) // iSCSI initiator service is not running
                                return new InitiatorException(error_description + " Is the iSCSI initiator running?", error_code, e);
                            else
                                return new InitiatorException(error_description, error_code, e);
                        }

                        // See if this is an iSCSI error
                        string iscsi_error_string = null;
                        try
                        {
                            iscsi_error_string = Enum.GetName(typeof(ISCSI_ERROR_CODES), error_code);
                            if (!String.IsNullOrEmpty(iscsi_error_string))
                                return new InitiatorException(iscsi_error_string, error_code, e);
                        }
                        catch (ArgumentException) { }

                        // We have an error code but can't decode it.  Log all the info we have and return an 'Unknown error'
                        Logger.Debug("Unrecognized error detected");
                        Logger.Debug("Status code = " + error_code);
                        foreach (PropertyData prop in e.ErrorInformation.Properties)
                        {
                            string value = "";
                            if (prop.Value != null)
                                value = prop.Value.ToString();
                            string type = "";
                            //if (prop.Type != null)
                            type = prop.Type.ToString();
                            Logger.Debug("    " + prop.Name + " => " + value + "  (" + type + ")");
                        }
                        return new InitiatorException("Unknown error " + error_code, error_code, e);
                    }
                }
            }

            // Look for recognizable WMI errors other than the dreaded "Generic failure"
            if (e.ErrorCode != ManagementStatus.Failed)
            {
                return new InitiatorException(e.ErrorCode.ToString(), e);
            }

            // If all else fails, call it an 'Unknown error' and log all the info we have
            Logger.Debug("Unrecognized error detected");
            foreach (PropertyData prop in e.ErrorInformation.Properties)
            {
                string value = "";
                if (prop.Value != null)
                    value = prop.Value.ToString();
                Logger.Debug("    " + prop.Name + " => " + value + "  (" + prop.Type.ToString() + ")");
            }
            return new InitiatorException("Unknown error", e);
        }

        private static InitiatorException VdsExceptionToInitiatorException(VdsException e)
        {
            if (e.InnerException != null)
                return ComExceptionToInitiatorException((COMException)e.InnerException);
            Regex re = new Regex(@"error code: (\d+)");
            Match m = re.Match(e.Message);
            if (m.Success)
            {
                long error_code = 0;
                if(long.TryParse(m.Groups[1].Value, out error_code))
                {
                    uint hresult = (uint)error_code;
                    string error_string = "";
                    try
                    {
                        error_string = Enum.GetName(typeof(VDS_COM_ERROR_CODES), hresult);
                    }
                    catch (ArgumentException) { }
                    if (!String.IsNullOrEmpty(error_string))
                    {
                        return new InitiatorException(error_string, hresult, e);
                    }
                }
            }
            return new InitiatorException(e.Message, e);
        }

        private static InitiatorException ComExceptionToInitiatorException(COMException e)
        {
            // See if the error is a standard Win32 error
            System.ComponentModel.Win32Exception w32ex = new System.ComponentModel.Win32Exception(e.ErrorCode);
            if (!w32ex.Message.StartsWith("Unknown error"))
                return new InitiatorException(w32ex.Message, (uint)e.ErrorCode, e);

            // See if the error is a known VDS error
            uint hresult = (uint)e.ErrorCode;
            string error_string = "";
            try
            {
                error_string = Enum.GetName(typeof(VDS_COM_ERROR_CODES), hresult);
            }
            catch (ArgumentException)
            {
                // If all else fails, call it an unknown error
                error_string = "Unknown error";
            }
            return new InitiatorException(error_string, hresult, e);
        }
        #endregion


        /// <summary>
        /// Run a system command and return the results
        /// </summary>
        /// <param name="Commandline"></param>
        /// <returns></returns>
        private ProcessResult RunCommand(string Commandline)
        {
            Logger.Debug("Executing system command '" + Commandline + "'");
            List<string> pieces = new List<string>(
                System.Text.RegularExpressions.Regex.Split(Commandline, @"\s+")
            );

            string filename = pieces[0];
            string args = String.Join(" ", pieces.ToArray(), 1, pieces.Count - 1);

            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = filename;
            p.StartInfo.Arguments = args;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.ErrorDialog = false;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();

            ProcessResult res = new ProcessResult();
            res.ExitCode = p.ExitCode;
            res.Stdout = stdout;
            res.Stderr = stderr;
            return res;
        }

        /// <summary>
        /// Create a new instance of a WMI class
        /// </summary>
        /// <param name="Namespace">The namespace of the class</param>
        /// <param name="ClassName">The name of the class</param>
        /// <returns></returns>
        private ManagementObject InstantiateWmiClass(string Namespace, string ClassName)
        {
            ManagementScope scope = ConnectWmiScope(Namespace);
            ManagementPath path = new ManagementPath(ClassName);
            ObjectGetOptions options = new ObjectGetOptions();
            ManagementClass object_class = new ManagementClass(scope, path, options);

            Logger.Debug("Creating instance of " + object_class.ClassPath);
            ManagementObject object_instance = object_class.CreateInstance();
            
            return object_instance;
        }

        /// <summary>
        /// Execute a WMI query and return the result
        /// </summary>
        /// <param name="WqlQueryString">The WQL query to execute</param>
        /// <param name="Namespace">The namespace to execute against</param>
        /// <returns></returns>
        private ManagementObjectCollection DoWmiQuery(string WqlQueryString, string Namespace = @"root\wmi")
        {
            Logger.Debug("Executing query " + WqlQueryString);

            ManagementScope scope = ConnectWmiScope(Namespace);
            ObjectQuery query = new ObjectQuery(WqlQueryString);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

            ManagementObjectCollection result_list = searcher.Get();
            try
            {
                // Calling Count forces WMI to execute the search, raising any exceptions here instead of later when iterating through the collection
                int count = result_list.Count;
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }

            return result_list;
        }

        /// <summary>
        /// Retrieve a mapping of device name to iSCSI volume name
        /// </summary>
        /// <param name="PortalAddressList">Only include devices from these portals</param>
        /// <param name="TargetList">Only include devices from these targets</param>
        /// <returns></returns>
        private Dictionary<string, string> GetDeviceToIscsiVolumeMap(List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            // Get the list of targets that match the specified filters
            HashSet<string> targets_to_query = GetFilteredTargetSet(PortalAddressList, TargetList);

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to targets and get the device that belongs to each one
            Dictionary<string, string> device_to_volume = new Dictionary<string, string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_name = session["SessionId"] as String;
                if (!String.IsNullOrEmpty(target_name) && targets_to_query.Contains(target_name))
                {
                    ManagementBaseObject[] device_info = session["Devices"] as ManagementBaseObject[]; // MSiSCSIInitiator_DeviceOnSession object
                    if (device_info == null || device_info.Length <= 0)
                    {
                        throw new InitiatorException("Session '" + session_name + "' for target '" + target_name + "' has no devices");
                    }

                    string device_name = device_info[0]["LegacyName"] as String;
                    string volume_name = IqnToVolumeName(target_name);

                    device_to_volume.Add(device_name, volume_name);
                }
            }

            return device_to_volume;
        }

        private string IqnToVolumeName(string pVolumeIqn)
        {
            // Derive volume name for known iSCSI storage systems

            if (pVolumeIqn.Contains("lefthand"))
            {
                // LeftHand system - volume name is the last piece
                string[] pieces = pVolumeIqn.Split(':');
                return pieces[pieces.Length - 1];
            }
            else if (pVolumeIqn.Contains("netapp"))
            {
                // Just based on a quick google search so this might be incorrect
                // NetApp filer - volume serial numer is the last piece
                string[] pieces = pVolumeIqn.Split(':');
                return pieces[pieces.Length - 1];
            }
            else if (pVolumeIqn.Contains("emc"))
            {
                // Just based on a quick google search so this might be incorrect
                // EMC vmax - volume name is the last piece
                string[] pieces = pVolumeIqn.Split('.');
                return pieces[pieces.Length - 1];
            }
            else if (pVolumeIqn.Contains("solidfire"))
            {
                // SolidFire system - volume name and volume ID are the 4th and 5th pieces
                string[] pieces = pVolumeIqn.Split('.');
                return pieces[4] + "." + pieces[5];
            }

            // Otherwise use the IQN for the name
            else
            {
                return pVolumeIqn;
            }
        }

        /// <summary>
        /// Get a list of iSCSI disk devices that match the specified filters
        /// </summary>
        /// <param name="PortalAddressList">Only include devices from these portals</param>
        /// <param name="TargetList">Only include devices from these targets</param>
        /// <returns></returns>
        private HashSet<string> GetFilteredDeviceList(List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            // Get the list of targets that match the specified filters
            HashSet<string> targets_to_query = GetFilteredTargetSet(PortalAddressList, TargetList);

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to targets and get the device that belongs to each one
            HashSet<string> filtered_device_list = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_name = session["SessionId"] as String;
                if (!String.IsNullOrEmpty(target_name) && targets_to_query.Contains(target_name))
                {
                    ManagementBaseObject[] device_info = session["Devices"] as ManagementBaseObject[]; // MSiSCSIInitiator_DeviceOnSession object
                    if (device_info == null || device_info.Length <= 0)
                    {
                        throw new InitiatorException("Session '" + session_name + "' for target '" + target_name + "' has no devices");
                    }
                    string device_name = device_info[0]["LegacyName"] as String;
                    filtered_device_list.Add(device_name);
                }
            }
            return filtered_device_list;
        }

        /// <summary>
        /// Return a set of targets that match the specified filters.
        /// </summary>
        /// <param name="PortalAddress">Only return targets that are on this portal</param>
        /// <param name="TargetList">Only return targets if they are in this list</param>
        /// <returns></returns>
        private HashSet<string> GetFilteredTargetSet(List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            bool filter_portal = PortalAddressList != null && PortalAddressList.Count >= 0;
            bool filter_target = TargetList != null && TargetList.Count >= 0;

            // Make a list of targets
            HashSet<string> filtered_target_names = new HashSet<string>();
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");
            foreach (ManagementObject target in target_list)
            {
                // Ignore this target is it is not on a requested portal
                string target_portal = GetTargetPortal(target);
                if (filter_portal && !PortalAddressList.Contains(target_portal))
                    continue;

                string target_iqn = target["TargetName"] as String;

                // Ignore this target if it is not in the specified list
                if (filter_target && !TargetList.Contains(target_iqn))
                    continue;

                filtered_target_names.Add(target_iqn);
            }

            return filtered_target_names;
        }

        /// <summary>
        /// Get the first portal this target is associated with.
        /// </summary>
        /// <param name="TargetObject">The target to query</param>
        /// <returns></returns>
        string GetTargetPortal(ManagementBaseObject TargetObject)
        {
            ManagementBaseObject[] portal_groups = TargetObject["PortalGroups"] as ManagementBaseObject[];
            foreach (ManagementBaseObject portal_group in portal_groups)
            {
                ManagementBaseObject[] portals = portal_group["Portals"] as ManagementBaseObject[];
                foreach (ManagementBaseObject portal in portals)
                {
                    return portal["Address"] as String;
                }
            }
            throw new InitiatorException("Could not find portal for target " + TargetObject["TargetName"] as String);
        }

        /// <summary>
        /// Log out of a single iSCSI session
        /// </summary>
        /// <param name="SessionObject">The session WMI object</param>
        private void LogoutSessionClassHelper(ManagementObject SessionObject)
        {
            ManagementBaseObject return_params = null;
            try
            {
                return_params = SessionObject.InvokeMethod("Logout", null, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
            CheckIscsiReturnCode((UInt32)return_params["ReturnValue"]);
        }

        /// <summary>
        /// Check if the reutrn code indicates success and raise an exception if not
        /// </summary>
        /// <param name="ReturnCode"></param>
        private void CheckIscsiReturnCode(UInt32 ReturnCode)
        {
            if (ReturnCode != 0)
            {
                string error_desc = "";
                try
                {
                    error_desc = Enum.GetName(typeof(ISCSI_ERROR_CODES), ReturnCode);
                }
                catch (ArgumentException)
                {
                    error_desc = "Unknown iSCSI error";
                }
                if (String.IsNullOrEmpty(error_desc))
                    error_desc = "Unknown iSCSI error";
                throw new InitiatorException(error_desc, ReturnCode);
            }
        }

        /// <summary>
        /// Login to a single iSCSI target
        /// </summary>
        /// <param name="TargetObject">The target WMI object</param>
        /// <param name="ChapUsername">Optional CHAP username</param>
        /// <param name="ChapInitSecret">Optional CHAP initiator password</param>
        /// <param name="MakePersistent">Create a persistent login</param>
        private void LoginTargetClassHelper(ManagementObject TargetObject, string ChapUsername = null, string ChapInitSecret = null, string ChapTargSecret = null, bool MakePersistent = false)
        {
            // Set or unset the target secret
            SetIscsiChapTargetSecret(ChapTargSecret);

            string target_name = TargetObject["TargetName"].ToString();

            // Set up parameters for login method call
            ManagementBaseObject method_params = TargetObject.GetMethodParameters("Login");

            if (!String.IsNullOrEmpty(ChapUsername) && !String.IsNullOrEmpty(ChapInitSecret))
            {
                // Set up login options for target to use
                ManagementObject login_options = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_TargetLoginOptions");
                login_options["Username"] = System.Text.Encoding.ASCII.GetBytes(ChapUsername);
                login_options["Password"] = System.Text.Encoding.ASCII.GetBytes(ChapInitSecret);
                if (String.IsNullOrEmpty(ChapTargSecret))
                    login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_CHAP_AUTH_TYPE;
                else
                    login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_MUTUAL_CHAP_AUTH_TYPE;
                method_params["LoginOptions"] = login_options;
            }

            // Call the Login method and check return code
            ManagementBaseObject return_params = null;
            try
            {
                return_params = TargetObject.InvokeMethod("Login", method_params, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
            CheckIscsiReturnCode((UInt32)return_params["ReturnValue"]);
            if (MakePersistent)
            {
                // To create a persistent connection, we need to call the Login method a second time with the IsPersistent flag set to true.
                // This doesn't actually log in again, but instead creates an entry in the persistent targets list to be logged in on the next boot.
                Logger.Debug("Creating persistent login for target '" + target_name + "'");
                method_params["IsPersistent"] = true;
                return_params = null;
                try
                {
                    return_params = TargetObject.InvokeMethod("Login", method_params, null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
                CheckIscsiReturnCode((UInt32)return_params["ReturnValue"]);
            }
        }

        /// <summary>
        /// Find the first available drive letter
        /// </summary>
        /// <returns></returns>
        private string GetFirstUnusedDriveLetter()
        {
            Service vds_service = ConnectVdsService();
            DriveLetterProperties[] all_letters = vds_service.QueryDriveLetters('A', 23);
            foreach (var letter in all_letters)
            {
                if (letter.Used == 0)
                    return new String(new char[] { letter.Letter });
            }
            throw new InitiatorException("No unused drive letters available");
        }

        /// <summary>
        /// Remove volume mount points from disk devices
        /// </summary>
        /// <param name="DeviceList">Only operate on these devices</param>
        /// <param name="PortalAddress">Only operate on devices from iSCSI targets on this portal</param>
        /// <param name="TargetList">Only operate on devices from these iSCSI targets</param>
        public void RemoveMountpoints(List<string> DeviceList = null, List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            // Filters
            bool filter_devices = DeviceList != null && DeviceList.Count > 0;
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> filtered_iscsi_device_list = new HashSet<string>();
            if (filter_iscsi)
            {
                filtered_iscsi_device_list = GetFilteredDeviceList(PortalAddressList, TargetList);
                if (filtered_iscsi_device_list.Count <= 0)
                    return;
            }

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            foreach (Pack disk_pack in vds_provider.Packs)
            {
                bool match = false;
                string dev_name = "";

                // Make sure this pack contains disks that meet the filter criteria
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                        IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                        !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                                                                        // Skip disks that have been deleted but not cleaned up yet
                    {
                        Logger.Debug("Skipping device " + dev_name);
                        break;
                    }

                    dev_name = disk.Name.Replace("?", ".");
                    if (filter_devices && !DeviceList.Contains(dev_name))
                        break;
                    if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                        break;

                    match = true;
                }
                if (!match)
                    continue;

                // Unmount the volumes
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (IsSystemVolume(vol))
                        break;

                    foreach (string mount_point in vol.AccessPaths)
                    {
                        Logger.Info("Removing access path " + mount_point + " from " + dev_name);
                        vol.DeleteAccessPath(mount_point, true);
                    }
                    vol.Refresh();
                }
            }
            vds_service.CleanupObsoleteMountPoints();
        }

        /// <summary>
        /// Check if a VDS disk object represents a system disk
        /// </summary>
        /// <param name="VdsDisk"></param>
        /// <returns></returns>
        private bool IsSystemDisk(AdvancedDisk VdsDisk)
        {
            return ((VdsDisk.Flags & DiskFlags.BootDisk) == DiskFlags.BootDisk ||
                    (VdsDisk.Flags & DiskFlags.CrashDumpDisk) == DiskFlags.CrashDumpDisk ||
                    (VdsDisk.Flags & DiskFlags.HibernationFileDisk) == DiskFlags.HibernationFileDisk ||
                    (VdsDisk.Flags & DiskFlags.PageFileDisk) == DiskFlags.PageFileDisk);
        }

        /// <summary>
        /// Check if a VDS volume object represents a system disk
        /// </summary>
        /// <param name="VdsVolume"></param>
        /// <returns></returns>
        private bool IsSystemVolume(Volume VdsVolume)
        {
            return ((VdsVolume.Flags & VolumeFlags.BootVolume) == VolumeFlags.BootVolume ||
                    (VdsVolume.Flags & VolumeFlags.CrashDump) == VolumeFlags.CrashDump ||
                    (VdsVolume.Flags & VolumeFlags.Hibernation) == VolumeFlags.Hibernation ||
                    (VdsVolume.Flags & VolumeFlags.PageFile) == VolumeFlags.PageFile ||
                    (VdsVolume.Flags & VolumeFlags.SystemVolume) == VolumeFlags.SystemVolume);
        }

        /// <summary>
        /// Check if a VDS disk object represents a disk that is still attached to the system
        /// </summary>
        /// <param name="VdsDisk"></param>
        /// <returns></returns>
        private bool IsStillAttached(Disk VdsDisk)
        {
            try
            {
                string a = VdsDisk.DevicePath;
                return true;
            }
            catch (System.Runtime.InteropServices.COMException e)
            {
                uint hresult = (uint)e.ErrorCode;
                if (hresult == (uint)VDS_COM_ERROR_CODES.VDS_E_OBJECT_DELETED ||
                    hresult == (uint)VDS_COM_ERROR_CODES.VDS_E_OBJECT_NOT_FOUND)
                {
                    return false;
                }
                else
                {
                    throw ComExceptionToInitiatorException(e);
                }
            }
        }

        private bool IsWhitelisted(Disk VdsDisk)
        {
            return IsWhitelisted(VdsDisk.DevicePath);
        }

        private bool IsWhitelisted(string DiskModel)
        {
            // No specific whitelist means every model is whitelisted
            if (mWhitelistedDiskModels.Count() <= 0)
                return true;

            foreach (string white in mWhitelistedDiskModels)
            {
                if (DiskModel.ToLower().Contains(white.ToLower()))
                    return true;
            }
            return false;
        }

        private bool IsBlacklisted(Disk VdsDisk)
        {
            return IsBlacklisted(VdsDisk.DevicePath);
        }

        private bool IsBlacklisted(string DiskModel)
        {
            // Whitelist takes priority
            if (!IsWhitelisted(DiskModel))
                return true;

            // No specific blacklist means no models are blacklisted
            if (mBlacklistedDiskModels.Count() <= 0)
                return false;

            foreach (string black in mBlacklistedDiskModels)
            {
                if (DiskModel.ToLower().Contains(black))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Unmount volumes and take disk devices offline
        /// </summary>
        /// <param name="DeviceList">Only operate on these devices</param>
        /// <param name="PortalAddress">Only operate on devices from iSCSI targets on this portal</param>
        /// <param name="TargetList">Only operate on devices from these iSCSI targets</param>
        /// <param name="ForceUnmount">Forceably unmount even if the device is in use</param>
        public void UnmountAndOfflineDisks(List<string> DeviceList = null, List<string> PortalAddressList = null, List<string> TargetList = null, bool ForceUnmount = false)
        {
            // Filters
            bool filter_devices = DeviceList != null && DeviceList.Count > 0;
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> filtered_iscsi_device_list = new HashSet<string>();
            if (filter_iscsi)
            {
                filtered_iscsi_device_list = GetFilteredDeviceList(PortalAddressList, TargetList);
                if (filtered_iscsi_device_list.Count <= 0)
                    return;
            }

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            // Go through disk packs and find disks
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = "";
                bool skip = false;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace("?", ".");

                    if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                        IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                        !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                    {
                        Logger.Debug("Skipping device " + dev_name);
                        skip = true;
                        break;
                    }

                    if (filter_devices && !DeviceList.Contains(dev_name))
                    {
                        skip = true;
                        break;
                    }
                    if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                    {
                        skip = true;
                        break;
                    }
                    break;
                }
                if (skip)
                    continue;

                // Unmount the volume
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (IsSystemVolume(vol))
                    {
                        Logger.Debug("Skipping volume " + vol.Label + " because it is a system volume");
                        skip = true;
                        break;
                    }

                    if (vol.IsMounted)
                    {
                        Logger.Debug("Unmounting volume " + vol.Label + " (disk " + dev_name + ")");
                        try
                        {
                            vol.Dismount(ForceUnmount, false);
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }
                    }
                }
                if (skip)
                    continue;

                // Offline the disk
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    if (disk.Status == DiskStatus.Online)
                    {
                        try
                        {
                            Logger.Debug("Offlining " + dev_name);
                            disk.Offline();
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Bring disk devices online and RW
        /// </summary>
        /// <param name="DeviceList">Only operate on these devices</param>
        /// <param name="PortalAddressList">Only operate on devices from iSCSI targets on these portals</param>
        /// <param name="TargetList">Only operate on devices from these iSCSI targets</param>
        public void OnlineDisks(List<string> DeviceList = null, List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            // Filters
            bool filter_devices = DeviceList != null && DeviceList.Count > 0;
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> filtered_iscsi_device_list = new HashSet<string>();
            if (filter_iscsi)
            {
                filtered_iscsi_device_list = GetFilteredDeviceList(PortalAddressList, TargetList);
                if (filtered_iscsi_device_list.Count <= 0)
                    return;
            }

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            // Find brand new disks and add them to VDS
            bool refresh_needed = false;
            foreach (AdvancedDisk disk in vds_service.UnallocatedDisks)
            {
                string dev_name = disk.Name.Replace("?", ".");

                if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                    IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                    !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                                                                    // Skip disks that have been deleted but not cleaned up yet
                {
                    Logger.Debug("Skipping device " + dev_name);
                    continue;
                }

                if (filter_devices && !DeviceList.Contains(dev_name))
                    continue;
                if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                    continue;

                if (disk.Status != DiskStatus.Online)
                {
                    Logger.Debug("Setting " + dev_name + " online");
                    try
                    {
                        disk.Online();
                    }
                    catch
                    {
                        Logger.Warn("Could not online " + dev_name);
                    }
                }
                if ((disk.Flags & DiskFlags.ReadOnly) == DiskFlags.ReadOnly)
                {
                    Logger.Debug("Setting " + dev_name + " to RW");
                    try
                    {
                        disk.ClearFlags(DiskFlags.ReadOnly);
                    }
                    catch
                    {
                        Logger.Warn("Could not clear RO flag on " + dev_name);
                    }
                }

                // Create a new 'pack' for the disk
                Pack new_pack = vds_provider.CreatePack();
                new_pack.AddDisk(disk.Id, PartitionStyle.Mbr, false);
                refresh_needed = true;
            }
            if (refresh_needed)
                vds_provider.Refresh();

            // Go through disk packs and find disks
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    string dev_name = disk.Name.Replace("?", ".");

                    if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                        IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                        !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                    {
                        Logger.Debug("Skipping device " + dev_name);
                        continue;
                    }

                    if (filter_devices && !DeviceList.Contains(dev_name))
                        continue;
                    if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                        continue;

                    if (disk.Status != DiskStatus.Online)
                    {
                        Logger.Debug("Setting " + dev_name + " online");
                        try
                        {
                            disk.Online();
                        }
                        catch
                        {
                            Logger.Warn("Could not online " + dev_name);
                        }
                    }
                    if ((disk.Flags & DiskFlags.ReadOnly) == DiskFlags.ReadOnly)
                    {
                        Logger.Debug("Setting " + dev_name + " to RW");
                        try
                        {
                            disk.ClearFlags(DiskFlags.ReadOnly);
                        }
                        catch
                        {
                            Logger.Warn("Could not clear RO flag on " + dev_name);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Create partitions and format disk devices
        /// </summary>
        /// <param name="DeviceList">Only operate on these devices</param>
        /// <param name="PortalAddressList">Only operate on devices from iSCSI targets on these portals</param>
        /// <param name="TargetList">Only operate on devices from these iSCSI targets</param>
        /// <param name="RelabelVolumes">Update the volume label to match the device/volume name (snapshots/clones)</param>
        public void PartitionAndFormatDisks(List<string> DeviceList = null, List<string> PortalAddressList = null, List<string> TargetList = null, bool RelabelVolumes = false)
        {
            // Filters
            bool filter_devices = DeviceList != null && DeviceList.Count > 0;
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> filtered_iscsi_device_list = new HashSet<string>();
            if (filter_iscsi)
            {
                filtered_iscsi_device_list = GetFilteredDeviceList(PortalAddressList, TargetList);
                if (filtered_iscsi_device_list.Count <= 0)
                    return;
            }
            Dictionary<string, string> iscsi_map = GetDeviceToIscsiVolumeMap();

            // Make sure disks are onlined/RW first
            OnlineDisks(DeviceList, PortalAddressList, TargetList);

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            // Find all appropriate disks in all disk packs and make sure they are partitioned, formatted and mounted
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                bool selected_disk = false;
                string volume_label = "";
                string volume_name = "";
                string dev_name = "";
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace("?", ".");
                    if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                        IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                        !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                    {
                        Logger.Debug("Skipping device " + dev_name);
                        continue;
                    }

                    if (filter_devices && !DeviceList.Contains(dev_name))
                        break;
                    if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                        break;

                    selected_disk = true;

                    // Partition and format the disk if it isn't already
                    if (disk.Partitions.Count <= 0)
                    {
                        iscsi_map.TryGetValue(dev_name, out volume_name);

                        // Partition the disk
                        if (String.IsNullOrEmpty(volume_name))
                            Logger.Info("Creating partition on " + dev_name);
                        else
                            Logger.Info("Creating partition on " + volume_name);
                        InputDisk indisk = new InputDisk();
                        indisk.DiskId = disk.Id;
                        indisk.Size = disk.Size - 3 * 1024 * 1024; // Must leave some free space on the drive for the dynamic disk database, even on a simple disk.  CreateVolume will fail without this
                        Async volume_create = null;
                        try
                        {
                            volume_create = disk_pack.BeginCreateVolume(VolumeType.Simple, new InputDisk[] { indisk }, 0, null, null);
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }

                        // Wait for partitioning to finish
                        while (!volume_create.IsCompleted)
                        {
                            Thread.Sleep(200);
                        }
                        Volume new_vol = disk_pack.EndCreateVolume(volume_create);
                        Thread.Sleep(1000);
                        new_vol.Mount();

                        new_vol.Refresh();

                        // Format the new volume
                        volume_label = dev_name.Substring(4);
                        if (String.IsNullOrEmpty(volume_name))
                        {
                            Logger.Info("Formatting " + dev_name);
                        }
                        else
                        {
                            Logger.Info("Formatting " + volume_name);
                            volume_label = volume_name;
                        }
                        try
                        {
                            Async volume_format = new_vol.BeginFormat(FileSystemType.Ntfs, volume_label, 0, true, true, false, null, null);

                            // Wait for format to complete
                            while (!volume_format.IsCompleted)
                            {
                                Thread.Sleep(200);
                            }
                            new_vol.EndFormat(volume_format);
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }
                    }

                    // Assume only a single disk per pack (simple volumes)
                    break;
                }
                if (!selected_disk)
                    continue;

                // Go through all volumes and make sure they are mounted
                disk_pack.Refresh();
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (!vol.IsMounted)
                    {
                        vol.Mount();
                    }

                    if (RelabelVolumes)
                    {
                        // Verify that the volume label is the same as the volume name, and relabel as necessary
                        // This is most relevant when cloning a volume
                        if (vol.Label != volume_label)
                        {
                            if (String.IsNullOrEmpty(volume_name))
                                Logger.Info("Updating volume label on " + dev_name);
                            else
                                Logger.Info("Updating volume label on " + volume_name);
                            // Oddly, I can't seem to find how to do this with VDS, so going back to plain WMI
                            // This requires using the Win32_LogicalDisk class, which is only intantiated for volumes that use drive letters
                            // So, temporarily mount this volume to a drive letter, change the label, then remove the drive letter
                            string drive_letter = GetFirstUnusedDriveLetter();
                            vol.AddAccessPath(drive_letter + @":\");
                            ManagementObject volume_obj = DoWmiQuery("SELECT * FROM Win32_LogicalDisk WHERE DeviceID = '" + drive_letter + ":'", @"root\cimv2").Cast<ManagementObject>().First();
                            try
                            {
                                volume_obj["VolumeName"] = volume_name;
                                volume_obj.Put();
                            }
                            catch (ManagementException e)
                            {
                                throw ManagementExceptionToInitiatorException(e);
                            }
                            finally
                            {
                                vol.DeleteAccessPath(drive_letter + @":\", true);
                            }
                        }
                    }

                    // Assume only a single volume/partition per disk
                    break;
                }
            }
        }

        /// <summary>
        /// Create mountpoints for disk devices
        /// </summary>
        /// <param name="DeviceList">Only operate on these devices</param>
        /// <param name="PortalAddressList">Only operate on devices from iSCSI targets on these portals</param>
        /// <param name="TargetList">Only operate on devices from these iSCSI targets</param>
        /// <param name="ForceMountPoints">Remove any drive letters and only use mount points</param>
        public void MountpointDisks(List<string> DeviceList = null, List<string> PortalAddressList = null, List<string> TargetList = null,bool ForceMountPoints = false)
        {
            // Filters
            bool filter_devices = DeviceList != null && DeviceList.Count > 0;
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> filtered_iscsi_device_list = new HashSet<string>();
            if (filter_iscsi)
            {
                filtered_iscsi_device_list = GetFilteredDeviceList(PortalAddressList, TargetList);
                if (filtered_iscsi_device_list.Count <= 0)
                    return;
            }
            Dictionary<string, string> iscsi_map = GetDeviceToIscsiVolumeMap();

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            foreach (Pack disk_pack in vds_provider.Packs)
            {
                bool match = false;
                string dev_name = "";

                // Make sure this pack contains appropriate disks that meet the filter criteria
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace("?", ".");
                    if (!IsStillAttached(disk) ||                       // Skip disks that have been deleted but not cleaned up yet
                        IsSystemDisk(disk) ||                           // Skip boot, system, pagefile, etc. disks
                        !IsWhitelisted(disk) || IsBlacklisted(disk))    // Skip drives based on whitelist/blacklist
                    {
                        Logger.Debug("Skipping device " + dev_name);
                        break;
                    }

                    if (filter_devices && !DeviceList.Contains(dev_name))
                        break;
                    if (filter_iscsi && !filtered_iscsi_device_list.Contains(dev_name))
                        break;

                    match = true;
                }
                if (!match)
                    continue;

                string volume_name = "";
                if (iscsi_map.Keys.Contains(dev_name))
                    volume_name = iscsi_map[dev_name];
                else
                    volume_name = dev_name.Substring(4);

                // Make sure all the volumes in this pack have a mount point
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (!vol.IsMounted)
                    {
                        vol.Mount();
                    }

                    if (ForceMountPoints)
                    {
                        // If this option is set, forceably remove drive letters and replace with folder mount points
                        // This usually is only relevant when Windows automounts a clone of another volume
                        vol.Refresh();
                        foreach (string mount_point in vol.AccessPaths)
                        {
                            // Mount points in this list are simple strings - 
                            // either drive letters:
                            //   J:\
                            // or folders:
                            //   C:\mnt\volume1

                            // Remove any mount points that are just drive letters
                            if (mount_point.Length < 4)
                            {
                                Logger.Debug("Removing mount point " + mount_point + " from " + volume_name);
                                vol.DeleteAccessPath(mount_point, true);
                            }
                        }
                    }

                    if (vol.AccessPaths.Count <= 0)
                    {
                        string mount_point = @"C:\mnt\" + volume_name + @"\";
                        Logger.Info("Mounting volume '" + volume_name + "' at '" + mount_point + "'");

                        // Create the mount point
                        Directory.CreateDirectory(mount_point);

                        // Mount the volume
                        vol.AddAccessPath(mount_point);
                    }
                    break; // Assume single partition per volume
                }
            }
        }

        /// <summary>
        /// Dump to the screen as much information as possible about the available VDS providers
        /// </summary>
        public void DebugShowAllVdsProviders()
        {
            Service vds_service = ConnectVdsService();
            vds_service.HardwareProvider = true;
            vds_service.SoftwareProvider = true;
            foreach (Provider provider in vds_service.Providers)
            {
                Logger.Info("Provider\n" + ObjectDumper.ObjectDumperExtensions.DumpToString<Provider>(provider, "provider"));
            }
        }

        /// <summary>
        /// Dump to the screen as much information as possible about the current disk devices
        /// </summary>
        public void DebugShowAllDiskDevices()
        {
            Logger.Info("==========================   Dumping VDS database  ==========================");
            Service vds_service = ConnectVdsService();
            foreach (AdvancedDisk disk in vds_service.UnallocatedDisks)
            {
                Logger.Info("Unallocated disk\n" + ObjectDumper.ObjectDumperExtensions.DumpToString<AdvancedDisk>(disk, "disk"));
            }
            Logger.Info("  ========================   Dynamic Disks  ========================");
            SoftwareProvider vds_provider = ConnectVdsProviderDynamic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                Logger.Info("Disk pack " + disk_pack.Name);
                Logger.Info("  ID = " + disk_pack.Id);
                Logger.Info("  Provider.Name = " + disk_pack.Provider.Name);
                Logger.Info("  Provider.ID = " + disk_pack.Provider.Id);
                Logger.Info("  Status = " + disk_pack.Status);
                Logger.Info("  Flags = " + disk_pack.Flags);
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    Logger.Info("Allocated disk\n" + ObjectDumper.ObjectDumperExtensions.DumpToString<AdvancedDisk>(disk, "disk"));
                }
            }

            Logger.Info("  ========================   Basic Disks  ========================");
            vds_provider = ConnectVdsProviderBasic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                Logger.Info("Disk pack " + disk_pack.Name);
                Logger.Info("  ID = " + disk_pack.Id);
                Logger.Info("  Provider.Name = " + disk_pack.Provider.Name);
                Logger.Info("  Provider.ID = " + disk_pack.Provider.Id);
                Logger.Info("  Status = " + disk_pack.Status);
                Logger.Info("  Flags = " + disk_pack.Flags);
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    Logger.Info("Allocated disk\n" + ObjectDumper.ObjectDumperExtensions.DumpToString<AdvancedDisk>(disk, "disk"));
                }
            }
            Logger.Info("==========================   Dumping Win32_DiskDrive database  ==========================");
            ManagementObjectCollection wmi_disk_list = DoWmiQuery("SELECT * FROM Win32_DiskDrive", @"root\cimv2");
            foreach (var disk in wmi_disk_list)
            {
                Logger.Info("Disk " + disk["Name"]);
                foreach (PropertyData prop in disk.Properties)
                {
                    Logger.Info("  " + prop.Name + " = " + prop.Value);
                }
            }
        }

        /// <summary>
        /// Wait for all iSCSI sessions to have valid disk devices
        /// </summary>
        private void WaitForDiskDevices()
        {
            Logger.Info("Waiting for disk devices");

            Logger.Debug("Waiting for all iSCSI sessions to have valid devices");
            bool retry = true;
            HashSet<string> expected_devices = new HashSet<string>();

            // Loop until we find valid devices for all targets
            while (retry)
            {
                retry = false;
                expected_devices = new HashSet<string>();

                // Get a list of session objects from the initiator
                ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

                // Find which targets have sessions (are logged in) and get their device info
                foreach (ManagementObject session in session_list)
                {
                    string target_name = session["TargetName"] as String;
                    string session_name = session["SessionId"] as String;
                    ManagementBaseObject[] device_info = session["Devices"] as ManagementBaseObject[]; // MSiSCSIInitiator_DeviceOnSession object
                    if (device_info == null || device_info.Length <= 0)
                    {
                        Logger.Debug("Session '" + session_name + "' for target '" + target_name + "' has no devices; retrying");
                        Thread.Sleep(5 * 1000);
                        retry = true;
                        break;
                    }
                    string device_name = device_info[0]["LegacyName"] as String;
                    if (String.IsNullOrEmpty(device_name))
                    {
                        Logger.Debug("Session '" + session_name + "' for target '" + target_name + "' has empty device name; retrying");
                        Thread.Sleep(5 * 1000);
                        retry = true;
                        break;
                    }
                    expected_devices.Add(device_name);
                }
            }

            // Wait until all of the volumes are present in the disk database
            Logger.Debug("Waiting for all volumes to be present in the disk database");
            Service vds_service = ConnectVdsService();
            List<SoftwareProvider> provider_list = new List<SoftwareProvider> { ConnectVdsProviderBasic(), ConnectVdsProviderDynamic() };
            HashSet<string> found_devices = new HashSet<string>();
            while (true)
            {
                found_devices = new HashSet<string>();
				foreach (AdvancedDisk disk in vds_service.UnallocatedDisks)
				{
					// It looks like VDS randomly returns an empty string for the FriendlyName if you have more than a handful of volumes, so this is not reliable.
					// Instead we made a list of expected devices up above from the list of active iSCSI sessions and look for each of those devices here
					string dev_name = disk.Name.Replace('?', '.');
					if (expected_devices.Contains(dev_name))
					{
						//Logger.Debug("  Found unallocated " + dev_name + " '" + disk.FriendlyName + "'");
						found_devices.Add(dev_name);
						continue;
					}
				}
                foreach (SoftwareProvider prov in provider_list)
                {
                    foreach (AdvancedDisk disk in vds_service.UnallocatedDisks)
                    {
                        // VDS seems to randomly return an empty string for the FriendlyName if you have more than a handful of volumes, so this is not reliable.
                        // Instead we made a list of expected devices up above from the list of active iSCSI sessions and look for each of those devices here
                        string dev_name = disk.Name.Replace('?', '.');
                        if (expected_devices.Contains(dev_name))
                        {
                            found_devices.Add(dev_name);
                            continue;
                        }
                    }
                    foreach (Pack disk_pack in prov.Packs)
                    {
                        foreach (AdvancedDisk disk in disk_pack.Disks)
                        {
                            //if (String.IsNullOrEmpty(disk.Name))
                            //{
                            //    Logger.Debug(disk.Id +  " has a null disk name");
                            //    continue;
                            //}
                            string dev_name = disk.Name.Replace('?', '.');
                            if (expected_devices.Contains(dev_name))
                            {
                                found_devices.Add(dev_name);
                                continue;
                            }
                        }
                    }
                }

                if (found_devices.Count >= expected_devices.Count)
                {
                    break;
                }
                else
                {
                    Logger.Debug("Found " + found_devices.Count + " / " + expected_devices.Count + " volumes");
                    StringBuilder missing = new StringBuilder();
                    foreach (string dev_name in expected_devices.Except(found_devices))
                    {
                        missing.Append(dev_name + ", ");
                    }
                    Logger.Debug("Missing " + missing.ToString().TrimEnd(',', ' '));
                    Thread.Sleep(5 * 1000);
                    vds_service = ConnectVdsService();
                    provider_list = new List<SoftwareProvider> { ConnectVdsProviderBasic(), ConnectVdsProviderDynamic() };
                }
            }
        }

        /// <summary>
        /// Add a new iSCSI target portal
        /// </summary>
        /// <param name="PortalAddress"></param>
        /// <param name="ChapUsername"></param>
        /// <param name="ChapInitSecret"></param>
        /// <param name="ChapTargSecret"></param>
        /// <param name="RefreshTargetList"></param>
        public void AddTargetPortal(string PortalAddress, string ChapUsername = null, string ChapInitSecret = null, string ChapTargSecret = null, bool RefreshTargetList = true)
        {
            // Set or unset the target secret
            SetIscsiChapTargetSecret(ChapTargSecret);

            // Create the new portal
            ManagementObject portal = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_SendTargetPortalClass");
            portal["PortalAddress"] = PortalAddress;
            portal["PortalPort"] = 3260;

            if (!String.IsNullOrEmpty(ChapUsername) && !String.IsNullOrEmpty(ChapInitSecret))
            {
                // Set up login options (CHAP)
                ManagementObject login_options = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_TargetLoginOptions");
                login_options["Username"] = System.Text.Encoding.ASCII.GetBytes(ChapUsername);
                login_options["Password"] = System.Text.Encoding.ASCII.GetBytes(ChapInitSecret);
                if (String.IsNullOrEmpty(ChapTargSecret))
                    login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_CHAP_AUTH_TYPE;
                else
                    login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_MUTUAL_CHAP_AUTH_TYPE;

                portal["LoginOptions"] = login_options;
            }

            // Commit the new portal to the initiator
            try
            {
                portal.Put();
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }

            if (RefreshTargetList)
            {
                // For some WMI reason we can't reuse the portal object we already have to simply execute methods like "Refresh", we have to get a new instance
                // Might as well call the helper function that does it all for us
                RefreshIscsiTargetPortals(new List<string>() { PortalAddress });
            }
        }

        /// <summary>
        /// Set the CHAP target secret
        /// </summary>
        /// <param name="TargetSecret"></param>
        public void SetIscsiChapTargetSecret(string TargetSecret)
        {
            ManagementObject init_methods = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass").Cast<ManagementObject>().First();
            ManagementBaseObject input_params = init_methods.GetMethodParameters("SetIScsiInitiatorCHAPSharedSecret");
            if (String.IsNullOrEmpty(TargetSecret))
                input_params["SharedSecret"] = null;
            else
                input_params["SharedSecret"] = System.Text.Encoding.ASCII.GetBytes(TargetSecret);
            try
            {
                init_methods.InvokeMethod("SetIScsiInitiatorCHAPSharedSecret", input_params, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
        }

        /// <summary>
        /// Remove the CHAP target secret
        /// </summary>
        public void ClearIscsiChapTargetSecret()
        {
            // Set or unset the target secret
            ManagementObject init_methods = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass").Cast<ManagementObject>().First();
            ManagementBaseObject input_params = init_methods.GetMethodParameters("SetIScsiInitiatorCHAPSharedSecret");
            input_params["SharedSecret"] = null;
            try
            {
                init_methods.InvokeMethod("SetIScsiInitiatorCHAPSharedSecret", input_params, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
        }

        /// <summary>
        /// Get a list of the currently configured iSCSI target portals
        /// </summary>
        /// <returns></returns>
        public List<IscsiPortalInfo> ListIscsiTargetPortals()
        {
            // Query the initiator for a list of target portals
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");

            // Iterate through list and make a list to return
            List<IscsiPortalInfo> portals_to_return = new List<IscsiPortalInfo>();

            foreach (ManagementObject portal_wmi in portal_list)
            {
                IscsiPortalInfo portal = new IscsiPortalInfo();
                portal.PortalAddress = portal_wmi["PortalAddress"] as String;
                portal.PortalPort = (UInt16)portal_wmi["PortalPort"];
                var login_options = portal_wmi["LoginOptions"] as ManagementBaseObject;
                portal.AuthType = ((ISCSI_AUTH_TYPES)(UInt32)login_options["AuthType"]).GetDescription();
                byte[] username_encoded = login_options["Username"] as byte[];
                if (username_encoded != null)
                    portal.Username = System.Text.Encoding.Default.GetString(username_encoded);
                portals_to_return.Add(portal);
            }
            return portals_to_return;
        }

        /// <summary>
        /// Remove the specified list of iSCSI target portals.  Pass null to remove all portals.
        /// </summary>
        /// <param name="PortalAddressList"></param>
        public void RemoveIscsiTargetPortals(List<string> PortalAddressList = null)
        {
            bool filter_portals = PortalAddressList != null && PortalAddressList.Count > 0;

            // Get a list of all target portals
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");

            // Make sure all the requested portals are in the list
            if (filter_portals)
            {
                string[] missing_portals = portal_list.Cast<ManagementObject>().Select(x => x["PortalAddress"] as String).Except(PortalAddressList).ToArray();
                if (missing_portals.Length > 0)
                {
                    throw new InitiatorException("Could not find requested portals: [" + String.Join(",", missing_portals) + "]");
                }
            }

            if (portal_list.Count <= 0)
            {
                return;
            }

            // Iterate through all portals and delete each one
            foreach (ManagementObject portal in portal_list)
            {
                string portal_address = portal["PortalAddress"] as String;
                if (filter_portals && !PortalAddressList.Contains(portal_address))
                    continue;

                Logger.Debug("Removing portal '" + portal_address + "'");
                try
                {
                    portal.Delete();
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
            }
        }
        
        /// <summary>
        /// Refresh the specified list of iSCSI target portals
        /// </summary>
        /// <param name="PortalAddressList"></param>
        public void RefreshIscsiTargetPortals(List<string> PortalAddressList = null)
        {
            if (PortalAddressList == null || PortalAddressList.Count <= 0)
            {
                // See if there are any portals to refresh
                ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");
                if (portal_list.Count <= 0)
                {
                    //See if there are still any targets left to clean up
                    ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");
                    if (target_list.Count <= 0)
                    {
                        return;
                    }
                }

                // Refresh all target portals
                ManagementObject init_methods = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass").Cast<ManagementObject>().First();
                try
                {
                    Logger.Debug("Requesting refresh for all portals");
                    init_methods.InvokeMethod("RefreshTargetList", null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
            }
            else
            {
                // Refresh each individual portal

                //
                // Note that calling Refresh on the SendTargetPortal object only shows when new volumes are created, but does not remove old volumes that were deleted.
                // Only RefreshTargetList on the MethodClass object fully refreshes portals, including removing targets, but it only operates on all targets at once.
                //

                ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");

                // Make sure all the requested portals are in the list
                string[] missing_portals = portal_list.Cast<ManagementObject>().Select(x => x["PortalAddress"] as String).Except(PortalAddressList).ToArray();
                if (missing_portals.Length > 0)
                {
                    throw new InitiatorException("Could not find requested portals: [" + String.Join(",", missing_portals) + "]");
                }
                
                foreach (ManagementObject portal in portal_list)
                {
                    string portal_address = portal["PortalAddress"] as String;
                    if (PortalAddressList.Contains(portal_address))
                    {
                        Logger.Debug("Reqesting refresh on " + portal_address);
                        try
                        {
                            portal.InvokeMethod("Refresh", null);
                        }
                        catch (ManagementException e)
                        {
                            throw ManagementExceptionToInitiatorException(e);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Get a list of iSCSI target information
        /// </summary>
        /// <param name="PortalAddressList">Only include targets from these portals</param>
        /// <param name="LoginState">Only include targets in this state</param>
        /// <returns></returns>
        public List<IscsiTargetInfo> ListIscsiTargets(List<string> PortalAddressList = null, IscsiTargetLoginState LoginState = IscsiTargetLoginState.Any, bool IncludeBootVolume = false)
        {
            bool filter_portal = PortalAddressList != null && PortalAddressList.Count > 0;

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in) and see if any look like the boot volume
            string boot_volume = "";
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                    targets_with_sessions.Add(target_name);

                // This is a pretty weak check - just looking that this device is not disk 0
                // But this should work with all known ways to configure boot from iSCSI
                var device_list = session["Devices"] as ManagementBaseObject[];
                UInt32 dev_number = (UInt32)device_list[0]["DeviceNumber"];
                if (dev_number == 0)
                    boot_volume = target_name;
            }

            List<IscsiTargetInfo> targets_to_return = new List<IscsiTargetInfo>();

            // Get the target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            foreach (ManagementObject target in target_list)
            {
                string target_name = target["TargetName"] as String;

                // Ignore targets with the wrong login state
                if (LoginState == IscsiTargetLoginState.LoggedIn && !targets_with_sessions.Contains(target_name))
                    continue;
                if (LoginState == IscsiTargetLoginState.LoggedOut && targets_with_sessions.Contains(target_name))
                    continue;

                // Ignore this target if it looks like the boot volume
                if (!IncludeBootVolume && target_name == boot_volume)
                    continue;
                
                // Get the portal address this target is associated with (assume only one)
                string target_portal = "";
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        target_portal = portal["Address"] as String;
                    }
                }

                // Ignore this target is it is not on a requested portal
                if (filter_portal && !PortalAddressList.Contains(target_portal))
                    continue;

                IscsiTargetInfo target_info = new IscsiTargetInfo();
                target_info.DiscoveryMechanism = target["DiscoveryMechanism"] as String;
                target_info.InitiatorName = target["InitiatorName"] as String;
                target_info.TargetFlags = (UInt32)target["TargetFlags"];
                target_info.TargetIqn = target_name;
                if (targets_with_sessions.Contains(target_info.TargetIqn))
                    target_info.IsLoggedIn = true;
                else
                    target_info.IsLoggedIn = false;
                target_info.TargetPortal = target_portal;

                // This never returns the CHAP info even when using CHAP - the class definition includes it but the values aren't present
                //var login_options = target["LoginOptions"] as ManagementBaseObject;
                //if (login_options != null)
                //{
                //    target_info.AuthType = ((ISCSI_AUTH_TYPES)(UInt32)login_options["AuthType"]).GetDescription();
                //    byte[] username_encoded = login_options["Username"] as byte[];
                //    target_info.Username = System.Text.Encoding.Default.GetString(username_encoded);
                //}

                targets_to_return.Add(target_info);
            }
            return targets_to_return;
        }

        /// <summary>
        /// Get a list of iSCSI session information
        /// </summary>
        /// <param name="PortalAddressList">Only include sessions from these portals</param>
        /// <param name="IncludeBootVolume">Include the boot volume if it is present (Boot from SAN)</param>
        /// <returns></returns>
        public List<IscsiSessionInfo> ListIscsiSessions(List<string> PortalAddressList = null, bool IncludeBootVolume = false)
        {
            bool filter_portal = PortalAddressList != null && PortalAddressList.Count > 0;

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            List<IscsiSessionInfo> sessions_to_return = new List<IscsiSessionInfo>();
            foreach (ManagementObject session in session_list)
            {
                var device_list = session["Devices"] as ManagementBaseObject[];
                UInt32 dev_number = (UInt32)device_list[0]["DeviceNumber"];

                // Make sure this is not the boot volume
                // This is a pretty weak check - just looking that this device is not disk 0
                // But this should work with all known ways to configure boot from iSCSI
                if (!IncludeBootVolume && dev_number == 0)
                    continue;

                IscsiSessionInfo sess = new IscsiSessionInfo();
                sess.DeviceNumber = dev_number;
                sess.LegacyDeviceName = device_list[0]["LegacyName"] as String;
                sess.InitiatorIqn = session["InitiatorName"] as string;
                sess.SessionId = session["SessionId"] as string;
                sess.TargetIqn = session["TargetName"] as string;
                var connection_list = session["ConnectionInformation"] as ManagementBaseObject[];
                foreach (var conn in connection_list)
                {
                    // We are assuming 1 connection per session
                    sess.InitiatorAddress = conn["InitiatorAddress"] as string;
                    sess.InitiatorPort = (UInt16)conn["InitiatorPort"];
                    sess.TargetAddress = conn["TargetAddress"] as string;
                    sess.TargetPort = (UInt16)conn["TargetPort"];
                }

                // Ignore targets that are not from the requested portals
                // The MS initiator is currently implemented such that the 'target address' for a session is actually the portal address, not the final endpoint of the session
                if (filter_portal && !PortalAddressList.Contains(sess.TargetAddress))
                    continue;

                sessions_to_return.Add(sess);
            }

            return sessions_to_return;
        }

        /// <summary>
        /// Log out of all of the sessions on iSCSI targets
        /// </summary>
        /// <param name="PortalAddress">Only log out of targets on this portal</param>
        /// <param name="TargetsToLogout">Only log out of these targets</param>
        /// <param name="RemovePersistent">Remove the persistent logins so the targets won't relogin after reboot</param>
        /// <returns>The number of targets logged out</returns>
        public int LogoutIscsiTargets(List<string> PortalAddressList = null, List<string> TargetsToLogout = null, bool RemovePersistent = true)
        {
            // Determine which targets we are supposed to log out of
            HashSet<string> filtered_target_names = GetFilteredTargetSet(PortalAddressList, TargetsToLogout);
            if (filtered_target_names.Count <= 0)
            {
                Logger.Warn("Did not find any targets to log in to");
                return 0;
            }

            // Make a lookup table of already existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject persistent_login in persistent_list)
            {
                persistent_logins.Add(persistent_login["TargetName"].ToString(), persistent_login);
            }

            // Get the list of target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to the list of targets and log out of them
            int logged_out_targets = 0;
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_id = session["SessionId"] as String;
                if (!String.IsNullOrEmpty(target_name) && filtered_target_names.Contains(target_name))
                {
                    // Log out of the session
                    Logger.Info("Logging out of session '" + session_id + "' for target '" + target_name + "'");
                    LogoutSessionClassHelper(session);
                    if (RemovePersistent && persistent_logins.ContainsKey(target_name))
                    {
                        Logger.Debug("Removing persistent login for target '" + target_name + "'");
                        try
                        {
                            persistent_logins[target_name].Delete();
                        }
                        catch (ManagementException e)
                        {
                            throw ManagementExceptionToInitiatorException(e);
                        }
                    }
                    logged_out_targets++;
                }
            }
            return logged_out_targets;
        }

        /// <summary>
        /// Remove all iSCSI persistent logins
        /// </summary>
        public void ClearIscsiPersistentLogins()
        {
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            foreach (ManagementObject persistent_login in persistent_list)
            {
                try
                {
                    persistent_login.Delete();
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
            }
        }

        /// <summary>
        /// Log in to iSCSI targets
        /// </summary>
        /// <param name="ChapUsername">Use this CHAP username for login</param>
        /// <param name="ChapInitSecret">Use this CHAP initiator secret for login</param>
        /// <param name="ChapTargSecret">Use this CHAP target secret for login</param>
        /// <param name="PortalAddressList">Only log in to targets from these portals</param>
        /// <param name="TargetsToLogin">Only log in to this list of targets</param>
        /// <param name="MakePersistent">Create persistent logins (relogin after reboot)</param>
        /// <returns></returns>
        public int LoginIscsiTargets(string ChapUsername = null, string ChapInitSecret = null, string ChapTargSecret = null, List<string> PortalAddressList = null, List<string> TargetsToLogin = null, bool MakePersistent = false)
        {
            // Determine which targets we are supposed to log in to
            HashSet<string> filtered_target_names = GetFilteredTargetSet(PortalAddressList, TargetsToLogin);
            if (filtered_target_names.Count <= 0)
            {
                Logger.Warn("Did not find any targets to log in to");
                return 0;
            }

            // Find which targets already have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name) && filtered_target_names.Contains(target_name))
                {
                    Logger.Debug("Target " + target_name + " already has one or more sessions");
                    targets_with_sessions.Add(target_name);
                }
            }

            // Make a table of existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject login in persistent_list)
            {
                string target = login["TargetName"] as String;
                persistent_logins.Add(target, login);
            }

            // Log in to each target
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");
            int logged_in_targets = 0;
            foreach (ManagementObject target in target_list)
            {
                string target_name = target["TargetName"] as String;
                if (String.IsNullOrEmpty(target_name))
                    continue;

                // Skip this target if it is not on the list
                if (!filtered_target_names.Contains(target_name))
                    continue;

                // Skip this target if it already has a session
                if (targets_with_sessions.Contains(target_name))
                    continue;

                // Remove the persistent login for this target if it exists
                if (persistent_logins.ContainsKey(target_name))
                {
                    Logger.Debug("Removing old persistent login for target '" + target_name + "'");
                    try
                    {
                        persistent_logins[target_name].Delete();
                    }
                    catch (ManagementException e)
                    {
                        throw ManagementExceptionToInitiatorException(e);
                    }
                }

                // Log in to the target
                Logger.Info("Logging in to target " + target_name);
                LoginTargetClassHelper(target, ChapUsername, ChapInitSecret, ChapTargSecret, MakePersistent);
                Logger.Debug("Logged in to target '" + target_name + "'");
                logged_in_targets++;
            }

            // Wait for the system to create devices and populate the disk database
            if (logged_in_targets > 0)
                WaitForDiskDevices();

            return logged_in_targets;
        }
        
        /// <summary>
        /// Get a list of disk devices connected to the system
        /// </summary>
        /// <param name="PortalAddressList">Only return iSCSI disks from these portals</param>
        /// <param name="TargetList">Only return iSCSI disks from these targets</param>
        /// <returns></returns>
        public List<DiskInfoDetailed> ListDiskInfo(List<string> PortalAddressList = null, List<string> TargetList = null)
        {
            List<DiskInfoDetailed> disks_to_return = new List<DiskInfoDetailed>();

            // Use to map devices to their iSCSI targets
            Logger.Debug("Querying iSCSI disk information");
            List<IscsiSessionInfo> iscsi_sessions = ListIscsiSessions();

            // Do we need to filter out any iSCSI volumes
            bool filter_iscsi = (PortalAddressList != null && PortalAddressList.Count > 0) || (TargetList != null && TargetList.Count > 0);
            HashSet<string> matching_iscsi_targets = null;
            if (filter_iscsi)
                matching_iscsi_targets = GetFilteredTargetSet(PortalAddressList, TargetList);

            Logger.Debug("Querying VDS disk information");
            Service vds = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                DiskInfoDetailed disk_info = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    disk_info = VdsDiskToDiskInfo(disk, iscsi_sessions, matching_iscsi_targets);
                }
                if (disk_info == null)
                    continue;

                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (vol.AccessPaths.Count > 0)
                        disk_info.MountPoint = vol.AccessPaths[0];
                    break; // assume a single volume
                }

                disks_to_return.Add(disk_info);
            }
            foreach (AdvancedDisk disk in vds.UnallocatedDisks)
            {
                DiskInfoDetailed disk_info = VdsDiskToDiskInfo(disk, iscsi_sessions, matching_iscsi_targets);
                if (disk_info != null)
                {
                    disks_to_return.Add(disk_info);
                }
            }

            Logger.Debug("Querying WMI disk information");
            // Make a lookup table of deviceID => serial number
            // At some points in time the serial number will come back as null, so we have to loop until we get it
            ManagementObjectCollection wmi_disk_list = DoWmiQuery("SELECT * FROM Win32_DiskDrive", @"root\cimv2");
            Dictionary<string, string> devid2serial = new Dictionary<string, string>();
            bool show_warning = true;
            DateTime start_time = DateTime.Now;
            while (true)
            {
                bool allgood = true;
                foreach (var disk in wmi_disk_list)
                {
                    string model = disk["Model"] as String;
                    if (model == null)
                    {
                        Logger.Debug(disk["DeviceID"] + " has a null model");
                    }

                    // Skip disks based on whitelist/blacklist
                    if (model != null && (!IsWhitelisted(model) || IsBlacklisted(model)))
                    {
                        continue;
                    }

                    string sernum = disk["SerialNumber"] as String;
                    if (sernum == null)
                    {
                        if (show_warning)
                        {
                            Logger.Warn("Detected null disk info; waiting for disk database to be up to date");
                            show_warning = false;
                        }
                        allgood = false;
                        break;
                    }
                    devid2serial.Add(((string)disk["PNPDeviceID"]).ToLower(), sernum);
                }
                if (allgood)
                    break;

                devid2serial.Clear();

                // Give up after 5 minutes
                if ((DateTime.Now - start_time).TotalSeconds > 300)
                    throw new InitiatorException("Could not query disk info from WMI");

                Thread.Sleep(3000);
                wmi_disk_list = DoWmiQuery("SELECT * FROM Win32_DiskDrive", @"root\cimv2");
            }

            foreach (var disk_info in disks_to_return)
            {
                string dev_id = disk_info.DevicePath.Substring(4).Replace("#", @"\").ToLower();
                dev_id = dev_id.Substring(0, dev_id.IndexOf('{') - 1);
                if (devid2serial.ContainsKey(dev_id))
                {
                    disk_info.EUISerialNumber = devid2serial[dev_id];
					disk_info.SolidfireClusterID = "";
					disk_info.SolidfireVolumeID = 0;

					// Try to parse SolidFire specific info
					if ((disk_info.EUISerialNumber != null && disk_info.EUISerialNumber.ToLower().Contains("f47acc")) ||
						(disk_info.IscsiTargetName != null && disk_info.IscsiTargetName.Contains("solidfire")))
					{
						for (int i = 0; i < 8; i += 2)
						{
							disk_info.SolidfireClusterID += Convert.ToChar(int.Parse(disk_info.EUISerialNumber.Substring(i, 2), System.Globalization.NumberStyles.AllowHexSpecifier));
						}
						disk_info.SolidfireVolumeID = int.Parse(disk_info.EUISerialNumber.Substring(8, 8), System.Globalization.NumberStyles.AllowHexSpecifier);
					}

                }
            }

            disks_to_return.Sort((x, y) => x.DeviceNumber.CompareTo(y.DeviceNumber));
            return disks_to_return;
        }

        /// <summary>
        /// Map a VDS disk object to a DiskInfo object.  Returns null if the disk is not an appropriate device,
        /// not a system volume, or (optionally) doesn't match the list of targets passed in
        /// </summary>
        /// <param name="VdsDisk">The VDS disk</param>
        /// <param name="IscsiSessions">The list of current iSCSI sessions</param>
        /// <param name="MatchIscsiTargets">Only return a value if the disk is from a session in this list</param>
        /// <returns></returns>
        private DiskInfoDetailed VdsDiskToDiskInfo(Disk VdsDisk, List<IscsiSessionInfo> IscsiSessions, HashSet<string> MatchIscsiTargets = null)
        {
            // Skip disks that have been deleted but not cleaned up yet
            if (!IsStillAttached(VdsDisk))
                return null;

            // Skip this disk if it is not an appropriate device
            if (!IsWhitelisted(VdsDisk.FriendlyName) || IsBlacklisted(VdsDisk.FriendlyName))
                return null;
            // VDS sometimes gets into a state where the FriendlyName it returns is an empty string, so we check the device path as well
            if (!IsWhitelisted(VdsDisk.DevicePath) || IsBlacklisted(VdsDisk.DevicePath))
                return null;

            bool filter_iscsi = MatchIscsiTargets != null && MatchIscsiTargets.Count > 0;

            // Skip this disk if it is not iSCSI and we are only looking for iSCSI disks
            if (filter_iscsi && VdsDisk.BusType != StorageBusType.Iscsi)
                return null;

            string dev_name = VdsDisk.Name.Replace("?", ".");
            uint dev_number = 0;
            Match m = Regex.Match(dev_name, @"(\d+)$");
            if (m.Success)
            {
                dev_number = uint.Parse(m.Groups[1].Value);
            }

            // Skip disk 0 because it is probably the system volume
            if (dev_number == 0)
                return null;

            // If this is an iSCSI disk, make sure it matches the filters passed in
            string target = null;
            string portal = null;
            if (VdsDisk.BusType == StorageBusType.Iscsi)
            {
                IscsiSessionInfo sess = (from s in IscsiSessions where s.LegacyDeviceName == dev_name select s).First();
                if (filter_iscsi && !MatchIscsiTargets.Contains(sess.TargetIqn))
                    return null;

                target = sess.TargetIqn;
                portal = sess.TargetAddress;
            }

            DiskInfoDetailed disk_info = new DiskInfoDetailed();
            disk_info.DevicePath = VdsDisk.DevicePath;
            disk_info.LegacyDeviceName = dev_name;
            disk_info.DeviceNumber = dev_number;
            disk_info.IscsiTargetName = target;
            disk_info.IscsiPortalAddress = portal;
            disk_info.SectorSize = VdsDisk.BytesPerSector;
            disk_info.Size = VdsDisk.Size;
            disk_info.Online = VdsDisk.Status == DiskStatus.Online;
            disk_info.Readonly = (VdsDisk.Flags & DiskFlags.ReadOnly) == DiskFlags.ReadOnly;
            if (VdsDisk.BusType == StorageBusType.Iscsi)
            {
                disk_info.TargetType = TargetType.iSCSI.ToString();
            }
            else if (VdsDisk.BusType == StorageBusType.Fibre)
            {
                disk_info.TargetType = TargetType.FibreChannel.ToString();
            }
            else
            {
                disk_info.TargetType = VdsDisk.BusType.ToString();
            }
            m = Regex.Match(VdsDisk.DiskAddress, @"Port(\d+)Path(\d+)Target(\d+)Lun(\d+)");
            if (m.Success)
            {
                disk_info.Port = uint.Parse(m.Groups[1].Value);
                disk_info.Path = uint.Parse(m.Groups[2].Value);
                disk_info.Target = uint.Parse(m.Groups[3].Value);
                disk_info.Lun = uint.Parse(m.Groups[4].Value);
            }

            return disk_info;
        }
        
        /// <summary>
        /// Get the current iSCSI initiator IQN name
        /// </summary>
        /// <returns></returns>
        public string GetIscsiInitiatorName()
        {
            string node_name = "";
            ManagementObjectCollection init_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass");
            foreach (ManagementObject init in init_list)
            {
                node_name = init["iSCSINodeName"] as String;
                break;
            }
            return node_name;
        }

        /// <summary>
        /// Set the iSCSI initiator IQN name
        /// </summary>
        /// <param name="NewInitiatorName">The new initiator name. Set to null to use the default name</param>
        public void SetIscsiInitiatorName(string NewInitiatorName = null)
        {
            ManagementObject init_methods = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass").Cast<ManagementObject>().First();
            ManagementBaseObject input_params = init_methods.GetMethodParameters("SetIscsiInitiatorNodeName");
            input_params["InitiatorNodeName"] = NewInitiatorName;
            try
            {
                init_methods.InvokeMethod("SetIscsiInitiatorNodeName", input_params, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
        }

        /// <summary>
        /// Get a list of the WWPNs from FC HBAs on this system
        /// </summary>
        /// <returns></returns>
        public List<string> ListWwpns()
        {
            List<string> wwns = new List<string>();
            ManagementObjectCollection adapter_list = DoWmiQuery("SELECT * FROM MSFC_FibrePortHBAAttributes");
            foreach (var adapter in adapter_list)
            {
                ManagementBaseObject attributes = adapter["Attributes"] as ManagementBaseObject;
                wwns.Add(String.Join(":", (attributes["PortWWN"] as byte[]).Select(x => String.Format("{0:X2}", x).ToLower()).ToArray()));
            }
            return wwns;
        }

        /// <summary>
        /// Get a list of installed FC HBAs and details about them
        /// </summary>
        /// <returns></returns>
        public List<FcHbaInfo> ListFcHbaInfo()
        {
            List<FcHbaInfo> hbas = new List<FcHbaInfo>();
            ManagementObjectCollection adapter_list = DoWmiQuery("SELECT * FROM MSFC_FCAdapterHBAAttributes");
            ManagementObjectCollection port_list = DoWmiQuery("SELECT * FROM MSFC_FibrePortHBAAttributes");
            ManagementObjectCollection adapter_methods_list = DoWmiQuery("SELECT * FROM MSFC_HBAFCPInfo");
            foreach (var adapter in adapter_list)
            {
                FcHbaInfo h = new FcHbaInfo();
                h.Description = adapter["ModelDescription"] as String;
                h.DriverVersion = adapter["DriverVersion"] as String;
                h.FirmwareVersion = adapter["FirmwareVersion"] as String;
                h.Model = adapter["Model"] as String;
                foreach (var port in port_list)
                {
                    if (port["InstanceName"] as String == adapter["InstanceName"] as String)
                    {
                        ManagementBaseObject attributes = port["Attributes"] as ManagementBaseObject;
                        h.WWPN = String.Join(":", (attributes["PortWWN"] as byte[]).Select(obj => String.Format("{0:X2}", obj).ToLower()).ToArray());

                        //h.PortState = Enum.GetName(typeof(HBA_PORTSTATE), (UInt32)attributes["PortState"]);
                        h.PortState = ((HBA_PORTSTATE)(UInt32)attributes["PortState"]).GetDescription();
                        //h.Speed = Enum.GetName(typeof(HBA_PORTSPEED), (UInt32)attributes["PortSpeed"]);
                        h.Speed = ((HBA_PORTSPEED)(UInt32)attributes["PortSpeed"]).GetDescription();

                        //Console.WriteLine("HBA port " + h.WWPN);

                        // Make a list of connected targets
                        byte[] wwn_array = attributes["PortWWN"] as byte[];
                        ManagementObject adapter_methods = null;
                        foreach (ManagementObject a in adapter_methods_list)
                        {
                            if (a["InstanceName"].ToString() == port["InstanceName"].ToString())
                            {
                                adapter_methods = a;
                                break;
                            }
                        }
                        HashSet<string> target_wwpns = new HashSet<string>();
                        HashSet<UInt32> lun_numbers = new HashSet<uint>();
                        int lun_paths = 0;
                        ManagementBaseObject in_params = adapter_methods.GetMethodParameters("GetFcpTargetMapping");
                        in_params["HbaPortWWN"] = wwn_array;
                        in_params["InEntryCount"] = 10;
                        ManagementBaseObject out_params = null;
                        try
                        {
                            out_params = adapter_methods.InvokeMethod("GetFcpTargetMapping", in_params, new InvokeMethodOptions());
                        }
                        catch (ManagementException e)
                        {
                            throw ManagementExceptionToInitiatorException(e);
                        }
                        ManagementBaseObject[] entry_list = out_params["Entry"] as ManagementBaseObject[];
                        if (entry_list != null)
                        {
                            foreach (ManagementBaseObject entry in entry_list)
                            {
                                var fcp_info = entry["FCPId"] as ManagementBaseObject;
                                string wwpn = String.Join(":", (fcp_info["PortWWN"] as byte[]).Select(obj => String.Format("{0:X2}", obj).ToLower()).ToArray());
                                target_wwpns.Add(wwpn);
                                //Console.WriteLine("Fcid: " + String.Format("{0:X}", (UInt32)fcp_info["Fcid"]));
                                //Console.WriteLine("FcpLun: " + String.Format("{0}", (UInt64)fcp_info["FcpLun"]));

                                var scsi_info = entry["ScsiID"] as ManagementBaseObject;
                                //Console.WriteLine("  ScsiBusNumber: " + (UInt32)scsi_info["ScsiBusNumber"]);
                                //Console.WriteLine("  ScsiTargetNumber: " + (UInt32)scsi_info["ScsiTargetNumber"]);
                                //Console.WriteLine("  ScsiOSLun: " + (UInt32)scsi_info["ScsiOSLun"]);
                                lun_numbers.Add((UInt32)scsi_info["ScsiOSLun"]);
                                lun_paths++;
                            }
                        }
                        h.TargetWWPNs = target_wwpns.ToList();
                        h.UniqueLunCount = lun_numbers.Count;
                        h.TotalLunPathCount = lun_paths;

                        //byte[] wwn_data = (((out_params["Entry"] as ManagementBaseObject[])[0]["FCPId"] as ManagementBaseObject)["PortWWN"] as byte[]);
                    }
                }
                hbas.Add(h);
            }
            return hbas;
        }

        /// <summary>
        /// Determine if MPIO is installed on the system
        /// </summary>
        /// <returns></returns>
        private bool MpioWmiInstalled()
        {
            try
            {
                DoWmiQuery("SELECT * FROM MPIO_REGISTERED_DSM");
                return true;
            }
            catch (InitiatorException e)
            {
                if (e.Message == "InvalidClass")
                {
                    return false;
                }
                else
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// Determine if there are any MPIO devices present on the system
        /// </summary>
        /// <returns></returns>
        private bool MpioDevicesPresent()
        {
            try
            {
                DoWmiQuery("SELECT * FROM DSM_LB_Operations");
                return true;
            }
            catch (InitiatorException e)
            {
                if (e.Message == "InvalidClass")
                {
                    // there are no MPIO devices
                    return false;
                }
                else
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// Set the specified load balance policy on all MPIO volumes
        /// </summary>
        /// <param name="NewPolicy">The policy to set</param>
        /// <param name="DeviceList">Only operate on these devices</param>
        public void SetMpioLoadBalancePolicy(DSM_LB_POLICY NewPolicy, List<string> DeviceList = null)
        {
            if (!MpioWmiInstalled())
            {
                throw new InitiatorException("MPIO is not installed");
            }
            if (!MpioDevicesPresent())
            {
                throw new InitiatorException("There are no MPIO devices");
            }

            Logger.Info("Setting load balancing policy to '" + NewPolicy + "'");

            bool device_filter = DeviceList != null && DeviceList.Count > 0;
            List<string> filtered_instances = new List<string>();
            if (device_filter)
            {
                filtered_instances = (from d in ListMpioDiskInfo() where DeviceList.Contains(d.LegacyDeviceName) select d.InstanceName).ToList();
            }

            ManagementObjectCollection dsm_ops_list = DoWmiQuery("SELECT * FROM DSM_LB_Operations");
            ManagementObjectCollection dsm_disk_list = DoWmiQuery("SELECT * FROM DSM_QueryLBPolicy_V2");
            UInt32 path_count = 4;
            foreach (var d in dsm_disk_list)
            {
                path_count = (UInt32)((ManagementBaseObject)d["LoadBalancePolicy"])["DSMPathCount"];
                break;
            }

            int path_to_prefer = 0;
            foreach (ManagementObject dsm_op in dsm_ops_list)
            {
                string op_instance = dsm_op["InstanceName"] as String;
                if (device_filter && !filtered_instances.Contains(op_instance))
                    continue;

                Logger.Debug("Setting LB policy on " + op_instance + " to " + (UInt32)NewPolicy);

                ManagementBaseObject lb_policy = InstantiateWmiClass(@"root\wmi", "DSM_Load_Balance_Policy_V2");
                lb_policy["Version"] = 2;
                lb_policy["Reserved"] = 0;
                lb_policy["LoadBalancePolicy"] = (UInt32)NewPolicy;
                foreach (ManagementBaseObject dsm_disk in dsm_disk_list)
                {
                    if (dsm_disk["InstanceName"] as String == op_instance)
                    {
                        ManagementBaseObject existing_lb_policy = dsm_disk["LoadBalancePolicy"] as ManagementBaseObject;

                        // Set the path flags.  All paths are marked as optimized and preferred for failback
                        // For the Failover LB policy, the first path is marked as primary and all others marked as standby
                        // For all other LB policies, all paths are marked as primary

                        ManagementBaseObject[] path_list = existing_lb_policy["DSM_Paths"] as ManagementBaseObject[];
                        for (int i = 0; i < path_list.Count(); i++)
                        {
                            path_list[i]["PreferredPath"] = 1;
                            path_list[i]["OptimizedPath"] = 1;
                            //if (NewPolicy == DSM_LB_POLICY.DSM_LB_FAILOVER && i > 0)
                            if (NewPolicy == DSM_LB_POLICY.DSM_LB_FAILOVER && i != path_to_prefer)
                            {
                                Logger.Debug("Setting path " + path_list[i]["DsmPathId"] + " to standby");
                                path_list[i]["PrimaryPath"] = 0;
                            }
                            else
                            {
                                Logger.Debug("Setting path " + path_list[i]["DsmPathId"] + " to primary");
                                path_list[i]["PrimaryPath"] = 1;
                            }
                        }
                        lb_policy["DSM_Paths"] = path_list;
                        lb_policy["DSMPathCount"] = (UInt32)existing_lb_policy["DSMPathCount"];
                        break;
                    }
                }

                ManagementBaseObject in_params = dsm_op.GetMethodParameters("DsmSetLoadBalancePolicy");
                in_params["LoadBalancePolicy"] = lb_policy;
                try
                {
                    dsm_op.InvokeMethod("DsmSetLoadBalancePolicy", in_params, new InvokeMethodOptions());
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
                path_to_prefer++;
                if (path_to_prefer >= path_count)
                    path_to_prefer = 0;
            }
        }

        /// <summary>
        /// Get a list of the load balance policy names on this system
        /// </summary>
        /// <returns></returns>
        public List<string> ListMpioLoadBalancePolicies()
        {
            return (from v in Enum.GetValues(typeof(DSM_LB_POLICY)).Cast<DSM_LB_POLICY>() select v.GetDescription()).ToList();
        }

        /// <summary>
        /// Get a list of all disks and their path info
        /// </summary>
        /// <returns></returns>
        public List<MpioDiskInfoDetailed> ListMpioDiskInfo()
        {
            // Get the basic disk info
            List<DiskInfoDetailed> simple_disk_list = ListDiskInfo();

            List<MpioDiskInfoDetailed> disks_to_return = new List<MpioDiskInfoDetailed>();
            foreach (var d in simple_disk_list)
                disks_to_return.Add(new MpioDiskInfoDetailed(d));

            if (!MpioWmiInstalled())
            {
                return disks_to_return;
            }
            if (!MpioDevicesPresent())
            {
                return disks_to_return;
            }

            ManagementObjectCollection dsm_disk_list = DoWmiQuery("SELECT * FROM DSM_QueryLBPolicy_V2");
            Dictionary<string, ManagementBaseObject> dsm_disks = new Dictionary<string, ManagementBaseObject>();
            foreach (var disk in dsm_disk_list)
            {
                string instance_name = disk["InstanceName"] as String;
                if (IsWhitelisted(instance_name) && !IsBlacklisted(instance_name))
                {
                    dsm_disks.Add(instance_name, disk);
                }
            }

            foreach (MpioDiskInfoDetailed mpio_disk_info in disks_to_return)
            {
                string dev_path = mpio_disk_info.DevicePath.Substring(4).Replace("#", @"\").ToLower();
                dev_path = dev_path.Substring(0, dev_path.IndexOf('{') - 1);
                string instance_name = (from k in dsm_disks.Keys where k.ToLower().StartsWith(dev_path) select k).First();
                var wmi_dsm_disk = dsm_disks[instance_name];

                mpio_disk_info.InstanceName = instance_name;
                var policy = wmi_dsm_disk["LoadBalancePolicy"] as ManagementBaseObject;
                mpio_disk_info.LoadBalancePolicy = ((DSM_LB_POLICY)(UInt32)policy["LoadBalancePolicy"]).GetDescription();
                var path_list = policy["DSM_Paths"] as ManagementBaseObject[];
                int failed_path_count = 0;
                foreach (var path in path_list)
                {
                    MpioPathInfoDetailed new_path = new MpioPathInfoDetailed();
                    new_path.ALUASupport = (UInt32)path["ALUASupport"];
                    new_path.DsmPathId = (UInt64)path["DsmPathId"];
                    new_path.FailedPath = (UInt32)path["FailedPath"];
                    new_path.OptimizedPath = (UInt32)path["OptimizedPath"];
                    new_path.PathWeight = (UInt32)path["PathWeight"];
                    new_path.PreferredPath = (UInt32)path["PreferredPath"];
                    new_path.PrimaryPath = (UInt32)path["PrimaryPath"];
                    new_path.Reserved = (UInt64)path["Reserved"];
                    if ((byte)path["SymmetricLUA"] == 0)
                        new_path.SymmetricLUA = false;
                    else
                        new_path.SymmetricLUA = true;
                    new_path.TargetPortGroup_Identifier = (UInt16)path["TargetPortGroup_Identifier"];
                    if ((byte)path["TargetPortGroup_Preferred"] == 0)
                        new_path.TargetPortGroup_Preferred = false;
                    else
                        new_path.TargetPortGroup_Preferred = true;
                    new_path.TargetPortGroup_State = ((TargetPortGroup_State)(UInt32)path["TargetPortGroup_State"]).GetDescription();

                    mpio_disk_info.DSM_Paths.Add(new_path);
                    if (new_path.FailedPath > 0)
                        failed_path_count++;
                }
                mpio_disk_info.FailedPathCount = failed_path_count;
            }

            ManagementObjectCollection mpio_list = DoWmiQuery("SELECT * FROM MPIO_GET_DESCRIPTOR");
            foreach (var disk in mpio_list)
            {
                string instance_name = disk["InstanceName"] as String;
                var mpio_disk_matches = (from d in disks_to_return where d.InstanceName == instance_name select d);

                if (mpio_disk_matches.Count() > 0)
                {
                    var mpio_disk = mpio_disk_matches.First();
                    mpio_disk.DeviceName = disk["DeviceName"] as String;
                    var pdo_list = disk["PdoInformation"] as ManagementBaseObject[];
                    foreach (var pdo_wmi in pdo_list)
                    {
                        UInt64 path_id = (UInt64)pdo_wmi["PathIdentifier"];
                        var scsi_addr = pdo_wmi["ScsiAddress"] as ManagementBaseObject;
                        var path_list = from p in mpio_disk.DSM_Paths where p.DsmPathId == path_id select p;
                        if (path_list.Count() > 0)
                        {
                            var path = path_list.First();
                            path.Lun = (byte)scsi_addr["Lun"];
                            path.PortNumber = (byte)scsi_addr["PortNumber"];
                            path.ScsiPathId = (byte)scsi_addr["ScsiPathId"];
                            path.TargetId = (byte)scsi_addr["TargetId"];
                        }
                        else
                        {
                            Logger.Debug("Could not find DSM path for " + mpio_disk.DeviceName + " path ID " + path_id);
                        }
                    }
                }
                else
                {
                    Logger.Debug("Could not find mpio disk for " + instance_name);
                }
            }

            ManagementObjectCollection dsm_lb_list = DoWmiQuery("SELECT * FROM DSM_QuerySupportedLBPolicies_V2");
            foreach (var lb_policies in dsm_lb_list)
            {
                string instance_name = lb_policies["InstanceName"] as String;
                var mpio_disk_matches = (from d in disks_to_return where d.InstanceName == instance_name select d);
                if (mpio_disk_matches.Count() > 0)
                {
                    var mpio_disk = mpio_disk_matches.First();
                    var policy_list = lb_policies["Supported_LB_Policies"] as ManagementBaseObject[];
                    foreach (var policy in policy_list)
                    {
                        mpio_disk.Supported_LB_Policies.Add(((DSM_LB_POLICY)(UInt32)policy["LoadBalancePolicy"]).GetDescription());
                    }
                }
            }

            disks_to_return.Sort((x, y) => x.DeviceNumber.CompareTo(y.DeviceNumber));
            return disks_to_return;
        }

        /// <summary>
        /// Enable the MPIO feature, and add the device string to the MS DSM
        /// The return value indicates if a reboot is required
        /// </summary>
        /// <returns></returns>
        public bool EnableMpio(string DeviceString)
        {
            Logger.Info("Enabling MPIO for '" + DeviceString + "' devices");
            bool reboot_required = false;

            //
            // Make sure the MPIO feature is turned on
            //

            // Get the current list of features and see if MPIO is enabled
            string cmd = "dism.exe /online /get-features";
            ProcessResult res = RunCommand(cmd);
            if (res.ExitCode != 0)
            {
                throw new InitiatorException("Failed to query MPIO feature - " + res.Stdout + res.Stderr);
            }
            bool mpio_enabled = false;
            string curr_feature = "";
            foreach (string line in Regex.Split(res.Stdout, "\n"))
            {
                string l = line.Trim();
                if (l.Length <= 0)
                    continue;

                var m = Regex.Match(l, @"Feature Name : (\S+)");
                if (m.Success)
                {
                    curr_feature = m.Groups[1].Value;
                    continue;
                }
                m = Regex.Match(l, @"State : (\S+)");
                if (m.Success && curr_feature == "MultipathIo")
                {
                    if (m.Groups[1].Value.ToLower() == "enabled")
                        mpio_enabled = true;
                    else
                        mpio_enabled = false;
                }
            }

            // Enable MPIO if it isn't already
            if (!mpio_enabled)
            {
                reboot_required = true;
                cmd = "dism.exe /online /enable-feature /featurename:MultipathIo /norestart";
                res = RunCommand(cmd);
                if (res.ExitCode != 0)
                {
                    throw new InitiatorException("Failed to install MPIO feature - " + res.Stdout + res.Stderr);
                }
            }

            //
            // Make sure the specified devices are added to the MS DSM
            //
            bool registered = false;

            // Check if the device string is already claimed by MPIO
            cmd = "mpclaim.exe -h";
            res = RunCommand(cmd);
            if (res.ExitCode != 0)
            {
                throw new InitiatorException("Failed to query for device string - " + res.Stdout + res.Stderr);
            }
            foreach (string line in Regex.Split(res.Stdout, "\n"))
            {
                if (line.Contains(DeviceString))
                {
                    registered = true;
                    break;
                }
            }

            // Add the device string to MPIO/MS DSM if it isn't already
            if (!registered)
            {
                reboot_required = true;
                cmd = "mpclaim.exe -n -i -d \"" + DeviceString + "\"";
                res = RunCommand(cmd);
                if (res.ExitCode != 0)
                {
                    throw new InitiatorException("Failed to register device string - " + res.Stdout + res.Stderr);
                }
            }

            // Make sure the MPIO WMI classes are present
            if (!MpioWmiInstalled())
                reboot_required = true;

            return reboot_required;

        /// <summary>
        /// Remove the specified device string from the MS DSM
        /// The return value indicates if a reboot is required
        /// </summary>
        /// <returns></returns>
        public bool DisableMpio(string DeviceString)
        {
            Logger.Info("Disabling MPIO for '" + DeviceString + "' devices");
            bool reboot_required = false;

            //
            // Make sure the devices are added to the MS DSM
            //
            bool registered = false;

            // Check if the device string is claimed by MPIO
            string cmd = "mpclaim.exe -h";
            ProcessResult res = RunCommand(cmd);
            if (res.ExitCode != 0)
            {
                throw new InitiatorException("Failed to query for device string - " + res.Stdout + res.Stderr);
            }
            foreach (string line in Regex.Split(res.Stdout, "\n"))
            {
                if (line.Contains(DeviceString))
                {
                    registered = true;
                    break;
                }
            }

            // Remove the device string from MPIO/MS DSM if it isn't already
            if (registered)
            {
                reboot_required = true;
                cmd = "mpclaim.exe -n -u -d \"" + DeviceString + "\"";
                res = RunCommand(cmd);
                if (res.ExitCode != 0)
                {
                    throw new InitiatorException("Failed to unregister device string - " + res.Stdout + res.Stderr);
                }
            }

            return reboot_required;
        }

        public bool VerifyPaths(int ExpectedVolumeCount, int ExpectedPathsPerVolume)
        {
            bool ret = true;

            List<MpioDiskInfoDetailed> volumes = ListMpioDiskInfo();
            if (volumes.Count == ExpectedVolumeCount)
            {
                Logger.Info("Found the expected number of volumes");
            }
            else
            {
                Logger.Error("Expected " + ExpectedVolumeCount + " volumes but found " + volumes.Count + " volumes");
                ret = false;
            }

            bool allgood = true;
            foreach (var vol in volumes)
            {
                if (vol.DSM_Paths.Count != ExpectedPathsPerVolume)
                {
                    Logger.Error("Volume " + vol.LegacyDeviceName + " has " + vol.DSM_Paths.Count + " total paths but expected " + ExpectedPathsPerVolume + " total paths");
                    allgood = false;
                    ret = false;
                    continue;
                }

                if (vol.DSM_Paths.Count - vol.FailedPathCount != ExpectedPathsPerVolume)
                {
                    Logger.Error("Volume " + vol.LegacyDeviceName + " has " + (vol.DSM_Paths.Count - vol.FailedPathCount) + " healthy paths but expected " + ExpectedPathsPerVolume + " healthy paths (" + vol.DSM_Paths.Count + " total paths, " + vol.FailedPathCount + " failed paths)");
                    allgood = false;
                    ret = false;
                    continue;
                }
                if (vol.FailedPathCount > 0 && vol.DSM_Paths.Count - vol.FailedPathCount >= ExpectedPathsPerVolume)
                {
                    Logger.Warn("Volume " + vol.LegacyDeviceName + " has " + vol.FailedPathCount + " failed paths, but " + (vol.DSM_Paths.Count - vol.FailedPathCount) + " healthy paths");
                }
            }
            if (allgood)
                Logger.Info("All volumes have the expected number of healthy paths");

            return ret;
        }
    }
}


using System;
using System.Collections.Generic;
using System.Management;
using System.Diagnostics;
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
using System.Security.Permissions; // PermissionSetAttribute

namespace windiskhelper
{
    class MicrosoftInitiator
    {
        public MicrosoftInitiator()
        {
            mClientHostname = "localhost";

            //Logger.Info("Connecting to local system");
            //ConnectWmiScope(@"root\wmi");
            //mVdsService = ConnectVdsService();
        }

        public MicrosoftInitiator(string pHostname, string pUsername, string pPassword)
        {
            mClientHostname = pHostname;
            mClientUsername = pUsername;
            mClientPassword = pPassword;

            //Logger.Info("Connecting to " + pHostname);
            //ConnectWmiScope(@"root\wmi");
            //mVdsService = ConnectVdsService();
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

        private ManagementScope ConnectWmiScope(string pNamespace, bool pReconnect = false)
        {
            if (wmiConnections.ContainsKey(pNamespace.ToLower()) && !pReconnect)
                return wmiConnections[pNamespace.ToLower()];

            ManagementPath path = null;
            ManagementScope scope = null;

            if (mClientHostname == "localhost")
            {
                Logger.Debug("Connecting to WMI scope '" + pNamespace + "' on localhost");
                path = new ManagementPath(pNamespace);
                scope = new ManagementScope(path);
            }
            else
            {
                if (mClientUsername != null)
                {
                    Logger.Debug("Connecting to WMI scope '" + pNamespace + "' on " + mClientHostname + " as " + mClientUsername + ":" + mClientPassword);
                    ConnectionOptions conn_options = new ConnectionOptions();
                    conn_options.Username = mClientUsername;
                    conn_options.Password = mClientPassword;
                    path = new ManagementPath(@"\\" + mClientHostname + "\\" + pNamespace);
                    scope = new ManagementScope(path, conn_options);
                }
                else
                {
                    Logger.Debug("Connecting to WMI scope '" + pNamespace + "' on " + mClientHostname + " as current user");
                    path = new ManagementPath(@"\\" + mClientHostname + "\\" + pNamespace);
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
                throw ComExceptionToIscsiException(e);
            }

            if (wmiConnections.ContainsKey(pNamespace.ToLower()))
                wmiConnections[pNamespace.ToLower()] = scope;
            else
                wmiConnections.Add(pNamespace.ToLower(), scope);

            return scope;
        }

        private Service ConnectVdsService(bool pReconnect = false)
        {
            if (mVdsService == null || pReconnect)
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
                    Logger.Debug("Scanning for disks...");
                    vds_service.Reenumerate();
                    Thread.Sleep(1000);
                    vds_service.Refresh();
                    Thread.Sleep(1000);
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
            else
            {
                mVdsService.Reenumerate();
                Thread.Sleep(1000);
                mVdsService.Refresh();
                Thread.Sleep(1000);
            }
            mVdsService.AutoMount = false;
            return mVdsService;
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

            //protected IscsiException(
            //  System.Runtime.Serialization.SerializationInfo info,
            //  System.Runtime.Serialization.StreamingContext context)
            //    : base(info, context) { }
        }

        public class IscsiTargetInfo
        {
            public string DiscoveryMechanism { get; set; }
            public string InitiatorName { get; set; }
            public string TargetPortal { get; set; }
            public string TargetIqn { get; set; }
            public UInt32 TargetFlags { get; set; }
            public bool IsLoggedIn { get; set; }
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
        }

        public enum TargetType
        {
            iSCSI,
            FibreChannel
        }
        public class DiskInfo
        {
            public string TargetName { get; set; }
            public string PortalAddress { get; set; }
            public uint DeviceNumber { get; set; }
            public string LegacyDeviceName { get; set; }
            public string MountPoint { get; set; }
            public int SectorSize { get; set; }
            public TargetType TargetType { get; set; }
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
        }

        public enum ISCSI_AUTH_TYPES : uint
        {
            ISCSI_NO_AUTH_TYPE = 0, // IQN authentication
            ISCSI_CHAP_AUTH_TYPE = 1, // One-way CHAP authentication
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
                Logger.Debug("    " + prop.Name + " => " + prop.Value.ToString() + "  (" + prop.Type.ToString() + ")");
            }
            return new InitiatorException("Unknown error", e);
            
        }

        private static InitiatorException VdsExceptionToInitiatorException(VdsException e)
        {
            if (e.InnerException != null)
                return ComExceptionToIscsiException((COMException)e.InnerException);
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

        private static InitiatorException ComExceptionToIscsiException(COMException e)
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


        private ManagementObject InstantiateWmiClass(string pNamespace, string pClassName)
        {
            ManagementScope scope = ConnectWmiScope(pNamespace);
            ManagementPath path = new ManagementPath(pClassName);
            ObjectGetOptions options = new ObjectGetOptions();
            ManagementClass object_class = new ManagementClass(scope, path, options);

            Logger.Debug("Creating instance of " + object_class.ClassPath);
            ManagementObject object_instance = object_class.CreateInstance();
            
            return object_instance;
        }

        private ManagementObjectCollection DoWmiQuery(string pWqlQueryString, string pNamespace = @"root\wmi")
        {
            ManagementScope scope = ConnectWmiScope(pNamespace);
            ObjectQuery query = new ObjectQuery(pWqlQueryString);
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

        private Dictionary<string, string> GetDeviceToVolumeMapAll()
        {
            Logger.Debug("Building device => volume map");
            Dictionary<string, string> device_to_volume = new Dictionary<string, string>();

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
                    throw new InitiatorException("Session '" + session_name + "' for target '" + target_name + "' has no devices");
                }

                // Weak check for boot/system volume
                if ((UInt32)device_info[0]["DeviceNumber"] == 0)
                {
                    Logger.Debug("Leaving " + target_name + " out of device map because it is probably a system volume");
                    continue;
                }
                string device_name = device_info[0]["LegacyName"] as String;
                string volume_name = IqnToVolumeName(target_name);

                device_to_volume.Add(device_name, volume_name);
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

        private Dictionary<string, string> GetDeviceToVolumeMapOnPortal(string pPortalAddress)
        {
            Logger.Info("Searching for disks from portal '" + pPortalAddress + "'");

            // Get the list of target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            // Make a list of targets on the specified portal
            HashSet<string> targets_to_mount = new HashSet<string>();
            foreach (ManagementObject target in target_list)
            {
                // This next line works with the current version of MS iSCSI but it's a hack based on the string format of the DiscoveryMechanism field
                //if (target["DiscoveryMechanism"].ToString().Contains(pPortalAddress.ToString())) { }

                // Get a list of portal groups, on each portal group get a list of portals, on each portal compare the portal address to the one we are looking for
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        if (portal["Address"].ToString() == pPortalAddress.ToString())
                        {
                            // This target is from the portal we are interested in
                            targets_to_mount.Add(target["TargetName"].ToString());
                        }
                    }
                }
            }

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to targets on the specified portal and get the device that belongs to each one
            Dictionary<string, string> device_to_volume = new Dictionary<string, string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_name = session["SessionId"] as String;
                if (!String.IsNullOrEmpty(target_name) && targets_to_mount.Contains(target_name))
                {
                    // This session is on the portal we are interested in
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

        private void LogoutSessionClassHelper(ManagementObject pSession)
        {
            string target_name = pSession["TargetName"] as String;
            string session_id = pSession["SessionId"] as String;
            Logger.Debug("Logging out of session '" + session_id + "' for target '" + target_name + "'");

            ManagementBaseObject return_params = null;
            try
            {
                return_params = pSession.InvokeMethod("Logout", null, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
            UInt32 return_code = (UInt32)return_params["ReturnValue"];
            if (return_code != 0)
            {
                string error_desc = "";
                try
                {
                    error_desc = Enum.GetName(typeof(ISCSI_ERROR_CODES), return_code);
                }
                catch (ArgumentException)
                {
                    error_desc = "Unknown iSCSI error";
                }
                if (String.IsNullOrEmpty(error_desc))
                    error_desc = "Unknown iSCSI error";
                throw new InitiatorException(error_desc, return_code);
            }
        }

        private void LoginTargetClassHelper(ManagementObject pTarget, string pChapUsername, string pChapSecret, bool pPersistent = false)
        {
            string target_name = pTarget["TargetName"].ToString();
            Logger.Info("Logging in to target " + target_name);

            // Set up parameters for login method call
            ManagementBaseObject method_params = pTarget.GetMethodParameters("Login");

            if (!String.IsNullOrEmpty(pChapUsername) && !String.IsNullOrEmpty(pChapSecret))
            {
                // Set up login options for target to use
                ManagementObject login_options = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_TargetLoginOptions");
                login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_CHAP_AUTH_TYPE;
                login_options["Username"] = System.Text.Encoding.ASCII.GetBytes(pChapUsername);
                login_options["Password"] = System.Text.Encoding.ASCII.GetBytes(pChapSecret);
                method_params["LoginOptions"] = login_options;
            }

            // Call the Login method and check return code
            ManagementBaseObject return_params = null;
            try
            {
                return_params = pTarget.InvokeMethod("Login", method_params, null);
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }
            UInt32 return_code = (UInt32)return_params["ReturnValue"];
            if (return_code != 0)
            {
                string error_desc = "";
                try
                {
                    error_desc = Enum.GetName(typeof(ISCSI_ERROR_CODES), return_code);
                }
                catch (ArgumentException)
                {
                    error_desc = "Unknown iSCSI error";
                }
                if (String.IsNullOrEmpty(error_desc))
                    error_desc = "Unknown iSCSI error";
                throw new InitiatorException(error_desc, return_code);
            }
            if (pPersistent)
            {
                // To create a persistent connection, we need to call the Login method a second time with the IsPersistent flag set to true.
                // This doesn't actually log in again, but instead creates an entry in the persistent targets list to be logged in on the next boot.
                Logger.Debug("Creating persistent login for target '" + target_name + "'");
                method_params["IsPersistent"] = true;
                return_params = null;
                try
                {
                    return_params = pTarget.InvokeMethod("Login", method_params, null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
                return_code = (UInt32)return_params["ReturnValue"];
                if (return_code != 0)
                {
                    string error_desc = "";
                    try
                    {
                        error_desc = Enum.GetName(typeof(ISCSI_ERROR_CODES), return_code);
                    }
                    catch (ArgumentException)
                    {
                        error_desc = "Unknown iSCSI error";
                    }
                    if (String.IsNullOrEmpty(error_desc))
                        error_desc = "Unknown iSCSI error";
                    throw new InitiatorException(error_desc, return_code);
                }
            }
        }

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

        private void RemoveMountsHelper(Dictionary<string, string> pDeviceToVolumeMap)
        {
            if (pDeviceToVolumeMap.Count <= 0)
                return;

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = null;
                string volume_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!pDeviceToVolumeMap.ContainsKey(dev_name))
                        continue;

                    volume_name = pDeviceToVolumeMap[dev_name];
                    break;
                }

                // Continue to the next pack if this one doesn't have disks in it
                if (volume_name == null) continue;

                // Unmount the volumes
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if ((vol.Flags & VolumeFlags.SystemVolume) == VolumeFlags.SystemVolume || (vol.Flags & VolumeFlags.BootVolume) == VolumeFlags.BootVolume)
                    {
                        Logger.Debug("Not removing mount points from " + volume_name + " because it is a system volume");
                        break;
                    }
                    foreach (string mount_point in vol.AccessPaths)
                    {
                        Logger.Debug("Removing access path " + mount_point + " from " + volume_name);
                        vol.DeleteAccessPath(mount_point, true);
                    }
                    vol.Refresh();
                    Thread.Sleep(1000);
                }
            }
            vds_service.CleanupObsoleteMountPoints();
        }

        private void UnmountHelper(Dictionary<string, string> pDeviceToVolumeMap, bool pForceUnmount)
        {
            if (pDeviceToVolumeMap.Count <= 0)
                return;

            Logger.Info("Unmounting disks");
            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                bool system_volume = false;
                string dev_name = null;
                string volume_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!pDeviceToVolumeMap.ContainsKey(dev_name))
                        continue;

                    volume_name = pDeviceToVolumeMap[dev_name];
                    break;
                }
                // Continue to the next pack if this one doesn't have disks in it
                if (volume_name == null) continue;

                // Unmount the volumes
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if ((vol.Flags & VolumeFlags.SystemVolume) == VolumeFlags.SystemVolume || (vol.Flags & VolumeFlags.BootVolume) == VolumeFlags.BootVolume)
                    {
                        Logger.Debug("Skipping " + volume_name + " because it is a system volume");
                        system_volume = true;
                        break;
                    }
                    foreach (string mount_point in vol.AccessPaths)
                    {
                        Logger.Debug("Removing access path " + mount_point + " from " + volume_name);
                        vol.DeleteAccessPath(mount_point, true);
                    }
                    vol.Refresh();

                    if (vol.IsMounted)
                    {
                        Logger.Debug("Unmounting " + volume_name);
                        try
                        {
                            vol.Dismount(pForceUnmount, false);
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }
                    }
                    Thread.Sleep(1000);
                }
                // Continue on to the next pack if this one contains a system volume
                if (system_volume)
                    continue;

                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    if (disk.Status == DiskStatus.Online)
                    {
                        try
                        {
                            Logger.Debug("Offlining " + volume_name);
                            disk.Offline();
                        }
                        catch (VdsException e)
                        {
                            throw VdsExceptionToInitiatorException(e);
                        }
                    }
                }
            }
            vds_service.CleanupObsoleteMountPoints();
        }
        
        private void OnlineAndPackHelper(Dictionary<string, string> pDeviceToVolumeMap)
        {
            if (pDeviceToVolumeMap.Count <= 0)
                return;

            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            HashSet<string> warned512e = new HashSet<string>();

            // Find brand new disks
            foreach (AdvancedDisk disk in vds_service.UnallocatedDisks)
            {
                string dev_name = disk.Name.Replace('?', '.');

                // Only look at the specified disks
                if (pDeviceToVolumeMap.ContainsKey(dev_name))
                {
                    string volume_name = null;

                    // See if this is a device we want to use
                    if (pDeviceToVolumeMap.ContainsKey(dev_name))
                        volume_name = pDeviceToVolumeMap[dev_name];
                    else
                        continue;

                    if (disk.BytesPerSector != 512 && !warned512e.Contains(volume_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(volume_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(volume_name);
                        }
                    }

                    // Make sure disk is online
                    Logger.Debug("Setting " + volume_name + " Online/RW");
                    if (disk.Status != DiskStatus.Online)
                    {
                        disk.Online();
                        disk.Refresh();
                    }
                    if ((disk.Flags & DiskFlags.ReadOnly) == DiskFlags.ReadOnly)
                    {
                        disk.ClearFlags(DiskFlags.ReadOnly);
                        disk.Refresh();
                    }
                    
                    // Create a new 'pack' for the disk
                    Pack new_pack = vds_provider.CreatePack();
                    new_pack.AddDisk(disk.Id, PartitionStyle.Mbr, false);
                }
            }

            // Find existing disks
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = null;
                string volume_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!pDeviceToVolumeMap.ContainsKey(dev_name))
                        continue;

                    volume_name = pDeviceToVolumeMap[dev_name];

                    if (disk.BytesPerSector != 512 && !warned512e.Contains(volume_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(volume_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(volume_name);
                        }
                    }

                    // Make sure disk is online
                    Logger.Debug("Setting " + volume_name + " Online/RW");
                    if (disk.Status != DiskStatus.Online)
                    {
                        try
                        {
                            disk.Online();
                            disk.Refresh();
                        }
                        catch
                        {
                            Logger.Warn("Could not online " + volume_name);
                        }
                    }
                    if ((disk.Flags & DiskFlags.ReadOnly) == DiskFlags.ReadOnly)
                    {
                        try
                        {
                            disk.ClearFlags(DiskFlags.ReadOnly);
                            disk.Refresh();
                        }
                        catch
                        {
                            Logger.Warn("Could not clear RO on " + volume_name);
                        }
                    }
                    break;
                }
            }
        }

        private void PartitionAndFormatHelper(Dictionary<string, string> pDeviceToVolumeMap, bool pRelabel = false)
        {
            if (pDeviceToVolumeMap.Count <= 0)
                return;

            // Assume disk == partition == volume == mount point
            // 1:1:1:1
            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            // Find all disks in all disk packs and make sure they are partitioned, formatted and mounted
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                HashSet<string> warned512e = new HashSet<string>();

                string dev_name = null;
                string volume_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!pDeviceToVolumeMap.ContainsKey(dev_name))
                        continue;

                    volume_name = pDeviceToVolumeMap[dev_name];

                    if (disk.BytesPerSector != 512)
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(volume_name + " is not using 512e - this can cause Windows issues.");
                        }
                    }

                    // Partition and format the disk if it isn't already
                    if (disk.Partitions.Count <= 0)
                    {
                        // Partition the disk
                        Logger.Info("Creating partition on '" + volume_name + "'");
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
                        Logger.Info("Formatting '" + volume_name + "'");
                        try
                        {
                            Async volume_format = new_vol.BeginFormat(FileSystemType.Ntfs, volume_name, 0, true, true, false, null, null);

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

                // Continue to the next pack if this one doesn't have disks in it
                if (volume_name == null) continue;
                Thread.Sleep(3000);

                // Go through all volumes and make sure they are mounted
                disk_pack.Refresh();
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (!vol.IsMounted)
                    {
                        vol.Mount();
                    }

                    if (pRelabel)
                    {
                        // Verify that the volume label is the same as the IQN name, and relabel as necessary
                        // This is most relevant when cloning a volume
                        if (vol.Label != volume_name)
                        {
                            Logger.Info("Updating volume label on " + volume_name);
                            // Oddly, I can't seem to find how to do this with VDS, so going back to plain WMI
                            // This requires using the Win32_LogicalDisk class, which is only intantiated for volumes that use drive letters
                            // So, temporarily mount this volume to a drive letter, change the label, then unmount the drive letter
                            string drive_letter = GetFirstUnusedDriveLetter();
                            vol.AddAccessPath(drive_letter + @":\");
                            ManagementObjectCollection vol_search = DoWmiQuery("SELECT * FROM Win32_LogicalDisk WHERE DeviceID = '" + drive_letter + ":'", @"root\cimv2");
                            foreach (ManagementObject vol_obj in vol_search)
                            {
                                try
                                {
                                    vol_obj["VolumeName"] = volume_name;
                                    vol_obj.Put();
                                }
                                catch (ManagementException e)
                                {
                                    throw ManagementExceptionToInitiatorException(e);
                                }
                                finally
                                {
                                    vol.DeleteAccessPath(drive_letter + @":\", true);
                                }
                                break;
                            }
                        }
                    }

                    // Assume only a single volume/partition per disk
                    break;
                }
            }
        }

        private void MountpointHelper(Dictionary<string, string> pDeviceToVolumeMap, bool pForceMountPoints = false)
        {
            if (pDeviceToVolumeMap.Count <= 0)
                return;

            // Assume disk == partition == volume == mount point
            // 1:1:1:1
            Service vds_service = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();

            HashSet<string> warned512e = new HashSet<string>();
            // Find all disks in all disk packs and make sure they are partitioned, formatted and mounted
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = null;
                string volume_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!pDeviceToVolumeMap.ContainsKey(dev_name))
                        continue;

                    volume_name = pDeviceToVolumeMap[dev_name];
                    if (disk.BytesPerSector != 512 && !warned512e.Contains(volume_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(volume_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(volume_name);
                        }
                    }
                    // Assume only a single disk per pack (simple volumes)
                    break;
                }

                // Continue to the next pack if this one doesn't have disks in it
                if (volume_name == null) continue;
                Thread.Sleep(3000);

                // Go through all volumes and make sure they are mounted
                disk_pack.Refresh();
                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (!vol.IsMounted)
                    {
                        vol.Mount();
                    }

                    if (pForceMountPoints)
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
                                Logger.Debug("Removing mount point " + mount_point + " from volume " + volume_name);
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

                    // Assume only a single volume/partition per disk
                    break;
                }
            }
        }

        public void DebugShowAllVDSProviders()
        {
            Service vds_service = ConnectVdsService();
            vds_service.HardwareProvider = true;
            vds_service.SoftwareProvider = true;
            foreach (Provider provider in vds_service.Providers)
            {
                Logger.Info("Provider\n" + ObjectDumper.ObjectDumperExtensions.DumpToString<Provider>(provider, "provider"));
            }
        }

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
        }

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

        private void ValidateChapUser(string pChapUser)
        {
            return;
            // This appears to be working better now
            //if (!Regex.IsMatch(pChapUser, "^[a-zA-Z0-9]+$"))
            //{
            //    throw new IscsiException("The Microsft iSCSI initiator is unreliable unless the CHAP username is strictly alphanumeric");
            //}
        }

        public void AddTargetPortal(string pPortalAddress, bool pRefreshTargetList = true)
        {
            AddTargetPortal(pPortalAddress, null, null, pRefreshTargetList);
        }

        public void AddTargetPortal(string pPortalAddress, string pChapUsername, string pChapSecret, bool pRefreshTargetList = true)
        {
            ValidateChapUser(pChapUsername);

            // Create the new portal
            ManagementObject portal = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_SendTargetPortalClass");
            portal["PortalAddress"] = pPortalAddress;
            portal["PortalPort"] = 3260;

            if (!String.IsNullOrEmpty(pChapUsername) && !String.IsNullOrEmpty(pChapSecret))
            {
                // Set up login options (CHAP)
                ManagementObject login_options = InstantiateWmiClass(@"root\wmi", "MSiSCSIInitiator_TargetLoginOptions");
                login_options["AuthType"] = ISCSI_AUTH_TYPES.ISCSI_CHAP_AUTH_TYPE;
                login_options["Username"] = System.Text.Encoding.ASCII.GetBytes(pChapUsername);
                login_options["Password"] = System.Text.Encoding.ASCII.GetBytes(pChapSecret);

                portal["LoginOptions"] = login_options;
            }

            // Commit the change to the initiator
            try
            {
                portal.Put();
            }
            catch (ManagementException e)
            {
                throw ManagementExceptionToInitiatorException(e);
            }

            if (pRefreshTargetList)
            {
                // For some WMI reason we can't reuse the portal object we already have to simply execute methods like "Refresh", we have to get a new instance
                // Might as well call the helper function taht does it all forus
                RefreshTargetPortal(pPortalAddress);
            }
        }

        public List<string> GetAllPortals()
        {
            // Query the initiator for a list of target portals
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");

            // Iterate through list and make a list to return
            List<string> portals_to_return = new List<string>();
            foreach (ManagementObject portal in portal_list)
            {
                string portal_address = portal["PortalAddress"] as String;
                if (!String.IsNullOrEmpty(portal_address))
                    portals_to_return.Add(portal_address);
            }
            return portals_to_return;
        }

        public void RemoveTargetPortal(string pPortalAddress)
        {
            // Search for the requested portal
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass WHERE PortalAddress = '" + pPortalAddress.ToString() + "'");
            if (portal_list.Count <= 0)
            {
                throw new InitiatorException("Could not find portal '" + pPortalAddress + "'");
            }

            foreach (ManagementObject portal in portal_list)
            {
                Logger.Debug("Removing portal '" + portal["PortalAddress"] + "'");
                try
                {
                    portal.Delete();
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }

                // If for some reason we found more than one portal with the requested address, break so we only operate on the first one
                break;
            }

        }

        public void RemoveAllTargetPortals()
        {
            // Get a list of all target portals
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass");
            if (portal_list.Count <= 0)
            {
                return;
            }

            // Iterate through all portals and delete each one
            foreach (ManagementObject portal in portal_list)
            {
                Logger.Debug("Removing portal '" + portal["PortalAddress"] + "'");
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

        public void RefreshAllPortals()
        {
            ManagementObjectCollection method_query = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass");
            foreach (ManagementObject method in method_query)
            {
                try
                {
                    Logger.Debug("Requesting refresh for all portals");
                    method.InvokeMethod("RefreshTargetList", null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
            }
            return;
        }

        public void RefreshTargetPortal(string pPortalAddress)
        {
            //
            // For some reason, calling Refresh on the SendTargetPortal object only shows when new volumes are created, but does not remove old volumes that were deleted.
            // Only RefreshTargetList on the MethodClass object fully refreshes portals, including removing targets, but it only operates on all targets at once.
            //

            // Get the portal object from the initiator
            Logger.Debug("Searching for portal '" + pPortalAddress + "'");
            ManagementObjectCollection portal_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SendTargetPortalClass WHERE PortalAddress = '" + pPortalAddress.ToString() + "'");
            if (portal_list.Count <= 0)
            {
                throw new InitiatorException("Could not find portal '" + pPortalAddress + "'");
            }

            foreach (ManagementObject portal in portal_list)
            {
                try
                {
                    string portal_address = portal["PortalAddress"] as String;
                    if (!String.IsNullOrEmpty(portal_address))
                        Logger.Debug("Requesting refresh on portal '" + portal_address + "'");

                    // Call the "Refresh" method to refresh the list of targets available on this target portal
                    portal.InvokeMethod("Refresh", null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }

                // If for some reason we found more than one portal with the requested address, break so we only operate on the first one
                break;
            }
        }

        public List<IscsiTargetInfo> GetLoggedInTargets()
        {
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                    targets_with_sessions.Add(target_name);
            }

            List<IscsiTargetInfo> targets_to_return = new List<IscsiTargetInfo>();

            // Get the target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            foreach (ManagementObject target in target_list)
            {
                // Ignore targets with no sessions
                if (!targets_with_sessions.Contains(target["TargetName"] as String))
                    continue;

                IscsiTargetInfo target_info = new IscsiTargetInfo();
                target_info.InitiatorName = target["InitiatorName"] as String;
                target_info.TargetFlags = (UInt32)target["TargetFlags"];
                target_info.TargetIqn = target["TargetName"] as String;
                if (targets_with_sessions.Contains(target_info.TargetIqn))
                    target_info.IsLoggedIn = true;
                else
                    target_info.IsLoggedIn = false;

                // Find the first target portal this target is associated with
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        target_info.TargetPortal = portal["Address"] as String;
                        break;
                    }
                    break;
                }
                targets_to_return.Add(target_info);
            }
            return targets_to_return;
        }

        public List<IscsiTargetInfo> GetLoggedOutTargets()
        {
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                    targets_with_sessions.Add(target_name);
            }

            List<IscsiTargetInfo> targets_to_return = new List<IscsiTargetInfo>();

            // Get the target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            foreach (ManagementObject target in target_list)
            {
                // Ignore targets with sessions
                if (targets_with_sessions.Contains(target["TargetName"] as String))
                    continue;

                IscsiTargetInfo target_info = new IscsiTargetInfo();
                target_info.InitiatorName = target["InitiatorName"] as String;
                target_info.TargetFlags = (UInt32)target["TargetFlags"];
                target_info.TargetIqn = target["TargetName"] as String;
                if (targets_with_sessions.Contains(target_info.TargetIqn))
                    target_info.IsLoggedIn = true;
                else
                    target_info.IsLoggedIn = false;

                // Find the first target portal this target is associated with
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        target_info.TargetPortal = portal["Address"] as String;
                        break;
                    }
                    break;
                }
                targets_to_return.Add(target_info);
            }
            return targets_to_return;
        }
        
        public List<IscsiTargetInfo> GetAllTargets()
        {
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                    targets_with_sessions.Add(target_name);
            }

            List<IscsiTargetInfo> targets_to_return = new List<IscsiTargetInfo>();

            // Get the target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            foreach (ManagementObject target in target_list)
            {
                IscsiTargetInfo target_info = new IscsiTargetInfo();
                target_info.InitiatorName = target["InitiatorName"] as String;
                target_info.TargetFlags = (UInt32)target["TargetFlags"];
                target_info.TargetIqn = target["TargetName"] as String;
                if (targets_with_sessions.Contains(target_info.TargetIqn))
                    target_info.IsLoggedIn = true;
                else
                    target_info.IsLoggedIn = false;

                // Find the first target portal this target is associated with
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        target_info.TargetPortal = portal["Address"] as String;
                        break;
                    }
                    break;
                }
                targets_to_return.Add(target_info);
            }
            return targets_to_return;
        }

        public List<IscsiSessionInfo> GetAllSessions(bool pIncludeBootVolume = false)
        {
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            List<IscsiSessionInfo> sessions_to_return = new List<IscsiSessionInfo>();
            foreach (ManagementObject session in session_list)
            {
                // Make sure this is not the boot volume
                // This is a pretty weak check - just looking that this device is not disk 0
                // But this should work with all known ways to configure boot from iSCSI
                if (!pIncludeBootVolume)
                {
                    var device_list = session["Devices"] as ManagementBaseObject[];
                    bool isboot = false;
                    foreach (var dev in device_list)
                    {
                        if ((UInt32)dev["DeviceNumber"] == 0)
                        {
                            isboot = true;
                            break;
                        }
                    }
                    if (isboot)
                        continue;
                }

                IscsiSessionInfo sess = new IscsiSessionInfo();
                sess.InitiatorIqn = session["InitiatorName"] as string;
                sess.SessionId = session["SessionId"] as string;
                sess.TargetIqn = session["TargetName"] as string;
                var connection_list = session["ConnectionInformation"] as ManagementBaseObject[];
                foreach (var conn in connection_list)
                {
                    // We are assuming 1 connection per session, which is the case for SolidFire
                    sess.InitiatorAddress = conn["InitiatorAddress"] as string;
                    sess.InitiatorPort = (UInt16)conn["InitiatorPort"];
                    sess.TargetAddress = conn["TargetAddress"] as string;
                    sess.TargetPort = (UInt16)conn["TargetPort"];
                }
                sessions_to_return.Add(sess);
            }

            return sessions_to_return;
        }

        public List<IscsiTargetInfo> GetTargetsOnPortal(String pPortalAddress)
        {
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                    targets_with_sessions.Add(target_name);
            }

            List<IscsiTargetInfo> targets_to_return = new List<IscsiTargetInfo>();

            // Get the target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            foreach (ManagementObject target in target_list)
            {
                // This works with the current version of MS iSCSI but it's a hack based on the string format of the DiscoveryMechanism field
                //if (target["DiscoveryMechanism"].ToString().Contains(pPortalAddress.ToString())) { }
 
                // Get a list of portal groups, on each portal group get a list of portals, on each portal compare the portal address to the one we are looking for
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        if (portal["Address"].ToString() == pPortalAddress.ToString())
                        {
                            // This target is from the portal we are interested in
                            IscsiTargetInfo target_info = new IscsiTargetInfo();
                            target_info.InitiatorName = target["InitiatorName"] as String;
                            target_info.TargetFlags = (UInt32)target["TargetFlags"];
                            target_info.TargetPortal = portal["Address"] as String;
                            target_info.TargetIqn = target["TargetName"] as String;
                            if (targets_with_sessions.Contains(target_info.TargetIqn))
                                target_info.IsLoggedIn = true;
                            else
                                target_info.IsLoggedIn = false;
                            targets_to_return.Add(target_info);
                        }
                    }
                }
            }

            return targets_to_return;
        }

        public void LogoutAllTargets(bool pRemovePersistent)
        {
            Logger.Info("Querying the list of targets/sessions");
            // Make a lookup table of already existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject persistent_login in persistent_list)
            {
                persistent_logins.Add(persistent_login["TargetName"].ToString(), persistent_login);
            }

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");
            
            // Log out of every session
            Logger.Info("Logging out all sessions");
            foreach (ManagementObject session in session_list)
            {
                // Make sure this is not the boot volume
                // This is a pretty weak check - just looking that this device is not disk 0
                // But this should work with all known ways to configure boot from iSCSI
                var device_list = session["Devices"] as ManagementBaseObject[];
                bool isboot = false;
                foreach (var dev in device_list)
                {
                    if ((UInt32)dev["DeviceNumber"] == 0)
                    {
                        isboot = true;
                        break;
                    }
                }
                if (isboot)
                    continue;

                LogoutSessionClassHelper(session);
                string target_name = session["TargetName"] as String;
                if (pRemovePersistent && persistent_logins.ContainsKey(target_name))
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
            }
        }

        public void RemovePersistentLogins()
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

        public void LogoutTargetsOnPortal(string pPortalAddress, bool pRemovePersistent)
        {
            // Make a lookup table of already existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject persistent_login in persistent_list)
            {
                persistent_logins.Add(persistent_login["TargetName"].ToString(), persistent_login);
            }

            // Get the list of target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            // Make a list of targets on the specified portal
            HashSet<string> targets_to_logout = new HashSet<string>();
            foreach (ManagementObject target in target_list)
            {
                // This works with the current version of MS iSCSI but it's a hack based on the string format of the DiscoveryMechanism field
                //if (target["DiscoveryMechanism"].ToString().Contains(pPortalAddress.ToString())) { }

                // Get a list of portal groups, on each portal group get a list of portals, on each portal compare the portal address to the one we are looking for
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        if (portal["Address"].ToString() == pPortalAddress.ToString())
                        {
                            // This target is from the portal we are interested in
                            targets_to_logout.Add(target["TargetName"].ToString());
                        }
                    }
                }
            }

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to targets on the specified portal and log out of them
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                if (!String.IsNullOrEmpty(target_name) && targets_to_logout.Contains(target_name))
                {
                    // Log out of the session
                    LogoutSessionClassHelper(session);
                    if (pRemovePersistent && persistent_logins.ContainsKey(target_name))
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
                }
            }
        }

        public void LoginAllTargets(bool pPersistent = false)
        {
            LoginAllTargets(null, null, pPersistent);
        }

        public void LoginAllTargets(string pChapUsername, string pChapSecret, bool pPersistent = false)
        {
            if (!String.IsNullOrEmpty(pChapUsername))
            {
                ValidateChapUser(pChapUsername);
            }

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name))
                {
                    Logger.Debug("Target " + target_name + " already has one or more sessions");
                    targets_with_sessions.Add(target_name);
                }
            }

            // Get a list of targets from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            // Make a lookup table of already existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject login in persistent_list)
            {
                string target = login["TargetName"] as String;
                persistent_logins.Add(target, login);
            }

            // Log in to each target that does not already have a session
            InitiatorException last_exception = null;
            foreach (ManagementObject target in target_list)
            {
                string target_name = target["TargetName"] as String;
                if (!String.IsNullOrEmpty(target_name) && !targets_with_sessions.Contains(target_name))
                {
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
                    try
                    {
                        LoginTargetClassHelper(target, pChapUsername, pChapSecret, pPersistent);
                    }
                    catch (InitiatorException e)
                    {
                        Logger.Error("Failed to log in: " + e.Message);
                        last_exception = e;
                    }
                    Logger.Info("Logged in to target '" + target_name + "'");
                }
            }

            // Wait for the system to create devices and populate the disk database
            WaitForDiskDevices();

            if (last_exception != null)
            {
                throw new InitiatorException("Could not log in to all targets");
            }
        }

        public void LoginTargetsOnPortal(string pPortalAddress, bool pPersistent = false)
        {
            LoginTargetsOnPortal(pPortalAddress, null, null, pPersistent);
        }

        public void LoginTargetsOnPortal(string pPortalAddress, string pChapUsername, string pChapSecret, bool pPersistent = false)
        {
            if (!String.IsNullOrEmpty(pChapUsername))
            {
                ValidateChapUser(pChapUsername);
            }

            // Make a list of targets that are on the requested portal
            HashSet<string> portal_target_names = new HashSet<string>();
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");
            foreach (ManagementObject target in target_list)
            {
                // There is a shortcut for this that works with the current version of MS iSCSI but it's a hack based on the string format of the DiscoveryMechanism field:
                //if (target["DiscoveryMechanism"].ToString().Contains(pPortalAddress.ToString())) { }

                // Get a list of portal groups, on each portal group get a list of portals, on each portal compare the portal address to the one we are looking for
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        if (portal["Address"].ToString() == pPortalAddress.ToString())
                        {
                            // This target is from the portal we are interested in
                            portal_target_names.Add(target["TargetName"] as String);
                        }
                    }
                }
            }


            // Find which targets have sessions (are logged in)
            HashSet<string> targets_with_sessions = new HashSet<string>();
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as string;
                if (target_name != null && !targets_with_sessions.Contains(target_name) && portal_target_names.Contains(target_name))
                {
                    Logger.Debug("Target " + target_name + " already has one or more sessions");
                    targets_with_sessions.Add(target_name);
                }
            }


            // Make a lookup table of already existing persistent logins
            ManagementObjectCollection persistent_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_PersistentLoginClass");
            Dictionary<string, ManagementObject> persistent_logins = new Dictionary<string, ManagementObject>();
            foreach (ManagementObject login in persistent_list)
            {
                string target = login["TargetName"] as String;
                persistent_logins.Add(target, login);
            }

            // Log in to each target on this portal that does not already have a session
            foreach (ManagementObject target in target_list)
            {
                string target_name = target["TargetName"] as String;

                // Skip this target if it is not on the requested portal
                if (!portal_target_names.Contains(target_name))
                    continue;

                if (!String.IsNullOrEmpty(target_name) && !targets_with_sessions.Contains(target_name))
                {
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
                    LoginTargetClassHelper(target, pChapUsername, pChapSecret, pPersistent);
                    Logger.Info("Logged in to target '" + target_name + "'");
                }
            }

            // Wait for the system to create devices and populate the disk database
            WaitForDiskDevices();
        }

        public void PartitionAndFormatDisksOnPortal(string pPortalAddress, bool pRelabel = false)
        {
            Service vds = ConnectVdsService();
            vds.Reenumerate();
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapOnPortal(pPortalAddress);
            OnlineAndPackHelper(device_to_volume);
            PartitionAndFormatHelper(device_to_volume, pRelabel);
        }

        public void MountpointDisksOnPortal(string pPortalAddress, bool pForceMountpoints = false)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapOnPortal(pPortalAddress);
            MountpointHelper(device_to_volume, pForceMountpoints);
        }
        
        public void RemoveMountpointsOnPortal(string pPortalAddress)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapOnPortal(pPortalAddress);
            RemoveMountsHelper(device_to_volume);
        }

        public void RemoveAllMountpoints()
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapAll();
            RemoveMountsHelper(device_to_volume);
        }

        public void UnmountDisksOnPortal(string pPortalAddress, bool pForceUnmount)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapOnPortal(pPortalAddress);
            UnmountHelper(device_to_volume, pForceUnmount);
        }
        
        public void UnmountAllDisks(bool pForceUnmount = false)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapAll();
            UnmountHelper(device_to_volume, pForceUnmount);
        }

        public void OnlineAllDisks()
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapAll();
            OnlineAndPackHelper(device_to_volume);
        }

        public void PartitionAndFormatAllDisks(bool pRelabel = false)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapAll();
            OnlineAndPackHelper(device_to_volume);
            PartitionAndFormatHelper(device_to_volume, pRelabel);
        }

        public void MountpointAllDisks(bool pForceMountpoints = false)
        {
            Dictionary<string, string> device_to_volume = GetDeviceToVolumeMapAll();
            MountpointHelper(device_to_volume, pForceMountpoints);
        }

        public List<DiskInfo> GetDiskInfoOnPortal(string pPortalAddress)
        {
            Logger.Debug("Querying disk information");
            // The list of objects to return
            Dictionary<string, DiskInfo> disk_list = new Dictionary<string, DiskInfo>();

            // Get the list of target objects from the initiator
            ManagementObjectCollection target_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_TargetClass");

            // Make a list of targets on the specified portal
            HashSet<string> targets_to_query = new HashSet<string>();
            foreach (ManagementObject target in target_list)
            {
                // This works with the current version of MS iSCSI but it's a hack based on the string format of the DiscoveryMechanism field
                //if (target["DiscoveryMechanism"].ToString().Contains(pPortalAddress.ToString())) { }

                // Get a list of portal groups, on each portal group get a list of portals, on each portal compare the portal address to the one we are looking for
                var portal_groups = target["PortalGroups"] as ManagementBaseObject[];
                foreach (var portal_group in portal_groups)
                {
                    var portals = portal_group["Portals"] as ManagementBaseObject[];
                    foreach (var portal in portals)
                    {
                        if (portal["Address"].ToString() == pPortalAddress.ToString())
                        {
                            // This target is from the portal we are interested in
                            targets_to_query.Add(target["TargetName"].ToString());
                        }
                    }
                }
            }

            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find the sessions that belong to targets on the specified portal and get the device that belongs to each one
            Dictionary<string, string> device_to_volume = new Dictionary<string, string>();
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_name = session["SessionId"] as String;
                if (!String.IsNullOrEmpty(target_name) && targets_to_query.Contains(target_name))
                {
                    // This session is on the portal we are interested in
                    ManagementBaseObject[] device_info = session["Devices"] as ManagementBaseObject[]; // MSiSCSIInitiator_DeviceOnSession object
                    if (device_info == null || device_info.Length <= 0)
                    {
                        throw new InitiatorException("Session '" + session_name + "' for target '" + target_name + "' has no devices");
                    }
                    ManagementBaseObject[] connection_info = session["ConnectionInformation"] as ManagementBaseObject[];

                    // We are assuming a single device per session, and a single connection per session

                    // Ignore disk 0 because it is probably the system volume
                    if ((uint)device_info[0]["DeviceNumber"] == 0)
                        continue;

                    DiskInfo disk_info = new DiskInfo();
                    disk_info.TargetName = target_name;
                    disk_info.DeviceNumber = (uint)device_info[0]["DeviceNumber"];
                    disk_info.LegacyDeviceName = device_info[0]["LegacyName"] as String;
                    disk_info.PortalAddress = connection_info[0]["TargetAddress"] as String;

                    disk_list.Add(disk_info.LegacyDeviceName, disk_info);
                }
            }

            // Assume disk == partition == volume == mount point
            // 1:1:1:1
            // Look for disks and the corresponding windows volumes
            Service vds = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();
            HashSet<string> warned512e = new HashSet<string>();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!disk_list.ContainsKey(dev_name))
                    {
                        dev_name = null;
                        break;
                    }
                    disk_list[dev_name].SectorSize = (int)disk.BytesPerSector;
                    if (disk.BytesPerSector != 512 && !warned512e.Contains(dev_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(dev_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(dev_name);
                        }
                    }
                    break;
                }
                if (dev_name == null) continue; // not a disk on the specified portal

                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (vol.AccessPaths.Count > 0)
                        disk_list[dev_name].MountPoint = vol.AccessPaths[0];
                    break; // assume a single volume
                }
            }
            // Look for brand new volumes not in a disk pack
            foreach (AdvancedDisk disk in vds.UnallocatedDisks)
            {
                string dev_name = disk.Name.Replace('?', '.');
                if (disk_list.ContainsKey(dev_name))
                {
                    disk_list[dev_name].SectorSize = (int)disk.BytesPerSector;
                    if (disk.BytesPerSector != 512 && !warned512e.Contains(dev_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(dev_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(dev_name);
                        }
                    }
                }
            }

            return disk_list.Values.ToList();
        }

        public List<DiskInfo> GetAllDiskInfo()
        {
            Logger.Debug("Querying disk information");
            // The list of objects to return
            Dictionary<string, DiskInfo> disk_list = new Dictionary<string, DiskInfo>();
            
            // Get a list of session objects from the initiator
            ManagementObjectCollection session_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_SessionClass");

            // Find which targets have sessions (are logged in) and get their device information
            foreach (ManagementObject session in session_list)
            {
                string target_name = session["TargetName"] as String;
                string session_name = session["SessionId"] as String;
                ManagementBaseObject[] device_info = session["Devices"] as ManagementBaseObject[]; // MSiSCSIInitiator_DeviceOnSession object
                if (device_info == null || device_info.Length <= 0)
                {
                    throw new InitiatorException("Session '" + session_name + "' for target '" + target_name + "' has no devices");
                }
                ManagementBaseObject[] connection_info = session["ConnectionInformation"] as ManagementBaseObject[];

                // We are assuming a single device per session, and a single connection per session

                // Ignore disk 0 because it is probably the system volume
                if ((uint)device_info[0]["DeviceNumber"] == 0)
                    continue;

                DiskInfo disk_info = new DiskInfo();
                disk_info.TargetType = TargetType.iSCSI;
                disk_info.TargetName = target_name;
                disk_info.DeviceNumber = (uint)device_info[0]["DeviceNumber"];
                disk_info.LegacyDeviceName = device_info[0]["LegacyName"] as String;
                disk_info.PortalAddress = connection_info[0]["TargetAddress"] as String;

                disk_list.Add(disk_info.LegacyDeviceName, disk_info);
            }

            // Assume disk == partition == volume == mount point
            // 1:1:1:1
            // Look for disks and the corresponding windows volumes
            HashSet<string> warned512e = new HashSet<string>();
            Service vds = ConnectVdsService();
            SoftwareProvider vds_provider = ConnectVdsProviderBasic();
            foreach (Pack disk_pack in vds_provider.Packs)
            {
                string dev_name = null;
                foreach (AdvancedDisk disk in disk_pack.Disks)
                {
                    dev_name = disk.Name.Replace('?', '.');
                    if (!disk_list.ContainsKey(dev_name))
                    {
                        dev_name = null;
                        break;
                    }
                    disk_list[dev_name].SectorSize = (int)disk.BytesPerSector;
                    if (disk.BytesPerSector != 512 && !warned512e.Contains(dev_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(dev_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(dev_name);
                        }
                    }
                    break; // assume a single disk
                }
                if (dev_name == null) continue;

                foreach (Volume vol in disk_pack.Volumes)
                {
                    if (vol.AccessPaths.Count > 0)
                        disk_list[dev_name].MountPoint = vol.AccessPaths[0];
                    break; // assume a single volume
                }
            }
            // Look for brand new volumes not yet in a disk pack
            foreach (AdvancedDisk disk in vds.UnallocatedDisks)
            {
                string dev_name = disk.Name.Replace('?', '.');
                if (disk_list.ContainsKey(dev_name))
                {
                    disk_list[dev_name].SectorSize = (int)disk.BytesPerSector;
                    if (disk.BytesPerSector != 512 && !warned512e.Contains(dev_name))
                    {
                        if (Environment.OSVersion.Version.Major < 6 ||
                            Environment.OSVersion.Version.Major >= 6 && Environment.OSVersion.Version.Minor < 2)
                        {
                            Logger.Warn(dev_name + " is not using 512e - this can cause Windows issues.");
                            warned512e.Add(dev_name);
                        }
                    }
                }
            }

            return disk_list.Values.ToList();
        }

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

        public void SetIscsiInitiatorName(string pInitiatorName)
        {
            ManagementObjectCollection init_list = DoWmiQuery("SELECT * FROM MSiSCSIInitiator_MethodClass");
            foreach (ManagementObject init in init_list)
            {
                ManagementBaseObject input_params = init.GetMethodParameters("SetIscsiInitiatorNodeName");
                input_params["InitiatorNodeName"] = pInitiatorName;
                try
                {
                    init.InvokeMethod("SetIscsiInitiatorNodeName", input_params, null);
                }
                catch (ManagementException e)
                {
                    throw ManagementExceptionToInitiatorException(e);
                }
                break;
            }
        }




        public List<string> GetWWPNs()
        {
            List<string> wwns = new List<string>();
            ManagementObjectCollection adapter_list = DoWmiQuery("SELECT * FROM MSFC_FibrePortHBAAttributes");
            foreach (var adapter in adapter_list)
            {
                ManagementBaseObject attributes = adapter["Attributes"] as ManagementBaseObject;
                wwns.Add(String.Join(":", (attributes["PortWWN"] as byte[]).Select(obj => String.Format("{0:X2}", obj).ToLower()).ToArray()));
            }
            return wwns;
        }

        public List<FcHbaInfo> GetFcHbaInfo()
        {
            List<FcHbaInfo> hbas = new List<FcHbaInfo>();
            ManagementObjectCollection adapter_list = DoWmiQuery("SELECT * FROM MSFC_FCAdapterHBAAttributes");
            ManagementObjectCollection port_list = DoWmiQuery("SELECT * FROM MSFC_FibrePortHBAAttributes");
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

                    }
                }
                hbas.Add(h);
            }
            return hbas;
        }


    
    }
}


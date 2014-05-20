using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Threading;

namespace windiskhelper
{
    class Program
    {
        const int EXIT_SUCCESS = 0;
        const int EXIT_FAIL = 1;
        const int EXIT_WARN = 2;

        static Program()
        {
            // Setup dynamic assembly loading from embedded resources
            // This will be called the first time an unknown type is referenced and load the requested assembly from the embedded resource
            // If the type is not one of ours, this call will fail and the resolver will move on to the GAC, etc.
            AppDomain.CurrentDomain.AssemblyResolve += (sender, eventargs) =>
            {
                String resourceName = typeof(Program).Namespace + "." + new AssemblyName(eventargs.Name).Name + ".dll";
                //Console.WriteLine("Looking for assembly " + resourceName);
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };

            // Add a handler to catch and log otherwise unhandled exceptions.
            AppDomain.CurrentDomain.UnhandledException += (object sender, UnhandledExceptionEventArgs e) =>
            {
                Logger.Error(e.ExceptionObject.ToString());
                Environment.Exit(EXIT_FAIL);
            };
        }

        static void Main(string[] args)
        {
            // Make sure we are running as an elevated user, or relaunch myself if not
            System.Security.Principal.WindowsPrincipal user = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
            if (!user.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("Restarting with elevation");
                System.Diagnostics.ProcessStartInfo pinfo = new System.Diagnostics.ProcessStartInfo();
                pinfo.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location;
                pinfo.Arguments = string.Join(" ", args);
                pinfo.Verb = "runas";
                System.Diagnostics.Process p = new System.Diagnostics.Process();
                p.EnableRaisingEvents = true;
                p.StartInfo = pinfo;
                try
                {
                    p.Start();
                    p.WaitForExit();
                    Environment.Exit(p.ExitCode);
                }
                catch (System.ComponentModel.Win32Exception e)
                {
                    Console.WriteLine(e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }

            // Setup dynamic assembly loading from embedded resources
            // This will be called the first time an unknown type is referenced and load the requested assembly from the embedded resource
            // If the type is not one of ours, this call will fail and the resolver will move on to the GAC, etc.
            AppDomain.CurrentDomain.AssemblyResolve += (sender, eventargs) =>
            {
                String resourceName = "windiskhelper." + new AssemblyName(eventargs.Name).Name + ".dll";
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };

            // Add a handler to catch and log otherwise unhandled exceptions.
            AppDomain.CurrentDomain.UnhandledException += (object sender, UnhandledExceptionEventArgs e) =>
            {
                Logger.Error(e.ExceptionObject.ToString());
                Environment.Exit(EXIT_FAIL);
            };

            // Parse and validate the command line
            CommandLineArguments Args = new CommandLineArguments(args);
            if (!ValidateArguments(Args)) Environment.Exit(EXIT_FAIL);

            // Print usage if the user gave no arguments or requested help
            if (args.Length < 1 || Args["help"] != null || Args["h"] != null || Args["?"] != null)
            {
                PrintUsage();
                Environment.Exit(EXIT_SUCCESS);
            }

            // Turn on batch mode if requested
            bool batch = false;
            if (Args["batch"] != null)
            {
                Logger.EnableBatchMode();
                batch = true;
            }
            bool json = false;
            if (Args["json"] != null)
            {
                Logger.EnableBatchMode();
                json = true;
            }

            // Turn on debug messages if requested
            if (Args["debug"] != null)
            {
                Logger.EnableConsoleDebug();
            }
            else
            {
                Logger.DisableConsoleDebug();
            }

            // Allow for the remote debugger to connect
            if (Args["wait_for_debug"] != null)
            {
                int wait_time = int.Parse(Args["wait_for_debug"]);
                //Logger.Info("Waiting " + wait_time + " sec for debug connection");
                //Thread.Sleep(wait_time * 1000);
                Logger.Info("Waiting up to " + wait_time + " sec for debug connection");
                DateTime start_time = DateTime.Now;
                while ((DateTime.Now - start_time).TotalSeconds < wait_time)
                {
                    Thread.Sleep(100);
                    if (System.Diagnostics.Debugger.IsAttached)
                        break;
                }
            }

            // Initialize the initiator object for remote or local connection
            MicrosoftInitiator msinit = null;
            if (Args["client_ip"] != null)
            {
                msinit = new MicrosoftInitiator(Args["client_ip"], Args["username"], Args["password"]);
            }
            else
            {
                msinit = new MicrosoftInitiator();
            }

            //
            // Execute the verb the user requested
            //

            if (Args["add_portal"] != null)
            {
                try
                {
                    if (Args["chap_user"] != null && Args["chap_secret"] != null)
                    {
                        Logger.Info("Adding portal '" + Args["portal_address"] + "' with CHAP user '" + Args["chap_user"] + "' and secret '" + Args["chap_secret"] + "'");
                        msinit.AddTargetPortal(Args["portal_address"], Args["chap_user"], Args["chap_secret"]);
                    }
                    else
                    {
                        Logger.Info("Adding portal '" + Args["portal_address"] + "'");
                        msinit.AddTargetPortal(Args["portal_address"]);
                    }
                    Logger.Info("Successfully added portal.");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    if (e.ErrorCode == (uint)MicrosoftInitiator.ISCSI_ERROR_CODES.ISDSC_CONNECTION_FAILED)
                    {
                        Logger.Warn("Portal was added, but initiator cannot connect to portal.");
                        Environment.Exit(EXIT_WARN);
                    }
                    else
                    {
                        Logger.Error("Add portal failed: " + e.Message);
                        LogExceptionDetail(e);
                        Environment.Exit(EXIT_FAIL);
                    }
                }
            }
            else if (Args["remove_portal"] != null)
            {
                Logger.Info("Removing portal '" + Args["portal_address"] + "'");
                try
                {
                    msinit.RemoveTargetPortal(Args["portal_address"]);
                    Logger.Info("Successfully removed portal.");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Remove portal failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_portals"] != null)
            {
                List<string> portal_list = null;
                try
                {
                    portal_list = msinit.GetAllPortals();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("List portals failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (string portal in portal_list)
                {
                    Logger.Info(portal);
                    if (batch)
                        Console.WriteLine(portal);
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(portal_list, Newtonsoft.Json.Formatting.Indented));
                Environment.Exit(EXIT_SUCCESS);
            }
            else if (Args["refresh_targets"] != null)
            {
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        Logger.Info("Refreshing targets on portal '" + Args["portal_address"] + "'");
                        // Currently this refresh doesn't remove old targets, only adds new ones
                        //MicrosoftInitiator.RefreshTargetPortal(Args["portal_address"]);
                        msinit.RefreshAllPortals();
                    }
                    else
                    {
                        Logger.Info("Refreshing target list on all portals...");
                        msinit.RefreshAllPortals();
                    }
                    Logger.Info("Successfully refreshed targets.");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Refresh failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_targets"] != null)
            {
                List<MicrosoftInitiator.IscsiTargetInfo> target_list = new List<MicrosoftInitiator.IscsiTargetInfo>();

                try
                {
                    if (Args["portal_address"] != null)
                    {
                        target_list = msinit.GetTargetsOnPortal(Args["portal_address"]);
                    }
                    else
                    {
                        target_list = msinit.GetAllTargets();
                    }
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.IscsiTargetInfo target in target_list)
                {
                    StringBuilder display_str = new StringBuilder();
                    display_str.Append(target.TargetPortal);
                    display_str.Append(" => " + target.TargetIqn);
                    if (target.IsLoggedIn)
                        display_str.Append(" (LOGGED IN)");
                    Logger.Info(display_str.ToString());
                    if (batch)
                        Console.WriteLine(display_str.ToString());
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(target_list, Newtonsoft.Json.Formatting.Indented));
                Environment.Exit(EXIT_SUCCESS);
            }
            else if (Args["list_sessions"] != null)
            {
                List<MicrosoftInitiator.IscsiSessionInfo> session_list = new List<MicrosoftInitiator.IscsiSessionInfo>();
                bool include_boot = false;
                if (Args["include_boot_vol"] != null)
                    include_boot = true;

                try
                {
                    if (Args["portal_address"] != null)
                    {
                        
                        //target_list = msinit.GetTargetsOnPortal(Args["portal_address"]);
                    }
                    else
                    {
                        session_list = msinit.GetAllSessions(include_boot);
                    }
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing sessions failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.IscsiSessionInfo session in session_list)
                {
                    StringBuilder display_str = new StringBuilder();
                    display_str.Append(session.SessionId + " => ");
                    display_str.Append(session.TargetIqn);
                    display_str.Append(", InitiatorIP: " + session.InitiatorAddress);
                    display_str.Append(", TargetIP: " + session.TargetAddress);

                    Logger.Info(display_str.ToString());
                    if (batch)
                        Console.WriteLine(display_str.ToString());
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(session_list, Newtonsoft.Json.Formatting.Indented));
                Environment.Exit(EXIT_SUCCESS);
            }
            else if (Args["login_targets"] != null)
            {
                bool persistent = false;
                if (Args["persistent"] != null)
                    persistent = true;
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        if (Args["chap_user"] != null && Args["chap_secret"] != null)
                        {
                            Logger.Info("Logging in to targets on portal '" + Args["portal_address"] + "' with CHAP user '" + Args["chap_user"] + "' and secret '" + Args["chap_secret"] + "'");
                            msinit.LoginTargetsOnPortal(Args["portal_address"], Args["chap_user"], Args["chap_secret"], persistent);
                        }
                        else
                        {
                            Logger.Info("Logging in to targets on portal '" + Args["portal_address"] + "'");
                            msinit.LoginTargetsOnPortal(Args["portal_address"], persistent);
                        }

                        Logger.Info("Onlining/signaturing all iSCSI disks");
                        msinit.OnlineAllDisks();
                    }
                    else
                    {
                        if (Args["chap_user"] != null && Args["chap_secret"] != null)
                        {
                            Logger.Info("Logging in to all targets with CHAP user '" + Args["chap_user"] + "' and secret '" + Args["chap_secret"] + "'");
                            msinit.LoginAllTargets(Args["chap_user"], Args["chap_secret"], persistent);
                        }
                        else
                        {
                            Logger.Info("Logging in to all targets");
                            msinit.LoginAllTargets(persistent);
                        }
                        
                        Logger.Info("Onlining/signaturing all iSCSI disks");
                        msinit.OnlineAllDisks();
                    }
                    Logger.Info("Successfully logged in to all targets.");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Login targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["logout_targets"] != null)
            {
                bool remove_persistent = false;
                if (Args["persistent"] != null)
                    remove_persistent = true;
                bool force = false;
                if (Args["force_unmount"] != null)
                    force = true;

                try
                {
                    if (Args["portal_address"] != null)
                    {
                        Logger.Info("Logging out of active targets on portal '" + Args["portal_address"] + "'");
                        if (force)
                            msinit.UnmountDisksOnPortal(Args["portal_address"], true);
                        msinit.LogoutTargetsOnPortal(Args["portal_address"], remove_persistent);
                    }
                    else
                    {
                        Logger.Info("Logging out of all active targets");
                        if (force)
                            msinit.UnmountAllDisks(true);
                        msinit.LogoutAllTargets(remove_persistent);
                    }
                    Logger.Info("Successfully logged out of all targets.");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Logout targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_disks"] != null)
            {
                List<MicrosoftInitiator.DiskInfo> disk_list = new List<MicrosoftInitiator.DiskInfo>();
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        disk_list = msinit.GetDiskInfoOnPortal(Args["portal_address"]);
                    }
                    else
                    {
                        disk_list = msinit.GetAllDiskInfo();
                    }
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.DiskInfo disk in disk_list)
                {
                    Logger.Info(disk.TargetName + " => " + disk.LegacyDeviceName + ", SectorSize: " + disk.SectorSize + ", Portal: " + disk.PortalAddress + ", MountPoint: " + disk.MountPoint);
                    if (batch)
                        Console.WriteLine(disk.TargetName + " => " + disk.LegacyDeviceName + ", SectorSize: " + disk.SectorSize + ", Portal: " + disk.PortalAddress + ", MountPoint: " + disk.MountPoint);
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(disk_list, Newtonsoft.Json.Formatting.Indented));

            }
            else if (Args["online_disks"] != null)
            {
                try
                {
                    Logger.Info("Onlining/signaturing all disks");
                    msinit.OnlineAllDisks();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Onlining disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["setup_disks"] != null)
            {
                bool force_mountpoints = false;
                if (Args["force_mountpoints"] != null)
                    force_mountpoints = true;
                bool relabel = false;
                if (Args["relabel"] != null)
                    relabel = true;
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        Logger.Info("Setting up disks on portal '" + Args["portal_address"] + "'");
                        msinit.PartitionAndFormatDisksOnPortal(Args["portal_address"], relabel);
                        msinit.MountpointDisksOnPortal(Args["portal_address"], force_mountpoints);
                    }
                    else
                    {
                        Logger.Info("Setting up all disks");
                        msinit.PartitionAndFormatAllDisks(relabel);
                        msinit.MountpointAllDisks(force_mountpoints);
                    }
                    Logger.Info("Successfully set up disks");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setup disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["format_disks"] != null)
            {
                bool relabel = false;
                if (Args["relabel"] != null)
                    relabel = true;
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        Logger.Info("Partitioning/formatting disks on portal '" + Args["portal_address"] + "'");
                        msinit.PartitionAndFormatDisksOnPortal(Args["portal_address"], relabel);
                    }
                    else
                    {
                        Logger.Info("Partitioning/formatting all disks");
                        msinit.PartitionAndFormatAllDisks(relabel);
                    }
                    Logger.Info("Successfully set up disks");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setup disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["unmount_disks"] != null)
            {
                try
                {
                    if (Args["portal_address"] != null)
                    {
                        Logger.Info("Removing mount points from disks on portal '" + Args["portal_address"] + "'");
                        msinit.RemoveMountpointsOnPortal(Args["portal_address"]);
                    }
                    else
                    {
                        Logger.Info("Removing mount points from all disks");
                        msinit.RemoveAllMountpoints();
                    }
                    Logger.Info("Successfully removed mounts");
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Unmount disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["show_initiatorname"] != null)
            {
                try
                {
                    string node_name = msinit.GetIscsiInitiatorName();
                    Logger.Info(node_name);
                    if (batch)
                        Console.WriteLine(node_name);
                    if (json)
                        Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(node_name, Newtonsoft.Json.Formatting.Indented));

                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Querying initiator name failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["set_initiatorname"] != null)
            {
                try
                {
                    msinit.SetIscsiInitiatorName(Args["name"]);
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setting initiator name failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["default_initiatorname"] != null)
            {
                try
                {
                    msinit.SetIscsiInitiatorName(null);
                    Environment.Exit(EXIT_SUCCESS);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setting initiator name failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["clean"] != null)
            {
                try
                {
                    Logger.Info("Logging out of all active targets");
                    msinit.LogoutAllTargets(true);
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Removing all target portals");
                    msinit.RemoveAllTargetPortals();
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Clearing target list");
                    msinit.RefreshAllPortals();
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Removing persistent logins");
                    msinit.RemovePersistentLogins();
                }
                catch (MicrosoftInitiator.InitiatorException) { }
            }
            else if (Args["dump_disk_info"] != null)
            {
                try
                {
                    Logger.Debug("dumping disk database");
                    Logger.Debug(msinit.ToString());
                    msinit.DebugShowAllDiskDevices();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Getting VDS info failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

            }
            else if (Args["dump_vds_prov_info"] != null)
            {
                try
                {
                    msinit.DebugShowAllVDSProviders();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Getting VDS info failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

            }

            else if (Args["show_wwpns"] != null)
            {
                List<string> wwns = new List<string>();
                try
                {
                    wwns = msinit.GetWWPNs();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Getting WWNs: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                Logger.Info("WWPNs: [" + String.Join(", ", wwns.ToArray()) + "]");
                if (batch)
                    Console.WriteLine(String.Join("\n", wwns.ToArray()));
                else if (json)
                {
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(wwns, Newtonsoft.Json.Formatting.Indented));
                }
            }
            else if (Args["show_hbas"] != null)
            {
                List<MicrosoftInitiator.FcHbaInfo> hbas = new List<MicrosoftInitiator.FcHbaInfo>();
                try
                {
                    hbas = msinit.GetFcHbaInfo();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Getting HBA info failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                Logger.Info("Found " + hbas.Count + " HBAs");
                foreach (var h in hbas)
                {
                    Logger.Info("");
                    Logger.Info("  Model:           " + h.Model);
                    Logger.Info("  Description:     " + h.Description);
                    Logger.Info("  WWN:             " + h.WWPN);
                    Logger.Info("  Speed:           " + h.Speed);
                    Logger.Info("  PortState:       " + h.PortState);
                    Logger.Info("  DriverVersion:   " + h.DriverVersion);
                    Logger.Info("  FirmwareVersion: " + h.FirmwareVersion);
                }
                if (batch)
                {
                    int index = 0;
                    foreach (var h in hbas)
                    {
                        Console.WriteLine("HBA " + index);
                        Console.WriteLine("  Model:           " + h.Model);
                        Console.WriteLine("  Description:     " + h.Description);
                        Console.WriteLine("  WWN:             " + h.WWPN);
                        Console.WriteLine("  Speed:           " + h.Speed);
                        Console.WriteLine("  PortState:       " + h.PortState);
                        Console.WriteLine("  DriverVersion:   " + h.DriverVersion);
                        Console.WriteLine("  FirmwareVersion: " + h.FirmwareVersion);
                        index++;
                    }
                }
                else if (json)
                {
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(hbas, Newtonsoft.Json.Formatting.Indented));
                }
            }

            Environment.Exit(EXIT_SUCCESS);
        }

        static void LogExceptionDetail(MicrosoftInitiator.InitiatorException e)
        {
            Logger.Debug("Error Code: " + e.Message);
            Logger.Debug(String.Format("HRESULT: 0x{0:X}", e.ErrorCode));
            Logger.Debug("Exception: " + e.ToString());
        }

        static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Usage: " + Assembly.GetEntryAssembly().GetName().Name + ".exe <verb> [options] [connection parameters]");
            Console.WriteLine();
            Console.WriteLine("Helper for the Microsoft iSCSI/FC Initiators");
            Console.WriteLine();
            Console.WriteLine("iSCSI Verbs:");
            Console.WriteLine("  --show_initiatorname  Display the current initiator IQN");
            Console.WriteLine("  --set_initiatorname   Change the current initiator IQN");
            Console.WriteLine("  --default_initiatorname   Change the current initiator IQN to the default");
            Console.WriteLine("                        Microsft value");
            Console.WriteLine("  --add_portal          add a target discovery portal to the initiator. Requires");
            Console.WriteLine("                        portal_address, and requires chap_user, chap_secret if");
            Console.WriteLine("                        using CHAP");
            Console.WriteLine("  --remove_portal       Remove a discovery portal from the initiator. Requires");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --list_portals        Display a list of the target portals");
            Console.WriteLine("  --list_targets        Display a list of discovered targets. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --list_sessions       Display a list of sessions. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --refresh_targets     Refresh the list of discovered targets.");
            Console.WriteLine("  --login_targets       Log in to discovered targets. Requires chap_user,");
            Console.WriteLine("                        chap_secret if using CHAP. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --logout_targets      Log out of connected targets. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine();
            Console.WriteLine("iSCSI Options:");
            Console.WriteLine("  --portal_address      The target portal address to use for the operation");
            Console.WriteLine("  --chap_user           The CHAP username to use for the operation");
            Console.WriteLine("  --chap_secret         The CHAP initiator secret to use for the operation");
            Console.WriteLine("  --persistent          Create a persistent login (reconnect after reboot) to");
            Console.WriteLine("                        the targets");
            Console.WriteLine("  --include_boot_vol    Include the iSCSI boot volume in whatever action you are trying");
            Console.WriteLine("                        to perform.  This only works for a narrow list of things");
            Console.WriteLine();
            Console.WriteLine("Fibre Channel Verbs:");
            Console.WriteLine("  --show_wwpns          Display the current initiator WWPNs");
            Console.WriteLine("  --show_hbas           Display the installed HBA info");
            Console.WriteLine();
            Console.WriteLine("Disk Management Verbs:");
            Console.WriteLine("  --list_disks          Display a list of targets and their corresponding");
            Console.WriteLine("                        devices and mount points. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --online_disks        Set all disks online and read-write");
            Console.WriteLine("  --format_disks        Create partitions and format the devices from");
            Console.WriteLine("                        logged in targets. Optionally include portal_address,");
            Console.WriteLine("                        relabel, force_mountpoints");
            Console.WriteLine("  --setup_disks         Create partitions, format and mount the devices from");
            Console.WriteLine("                        logged in targets. Optionally include portal_address,");
            Console.WriteLine("                        relabel, force_mountpoints");
            Console.WriteLine("  --unmount_disks       Remove mount points and drive letters from logged in targets");
            Console.WriteLine("  --dump_disk_info      Print out as much information as possible about the connected");
            Console.WriteLine("                        disk devices on the system");
            Console.WriteLine("  --dump_vds_prov_info  Print out as much information as possible about the VDS");
            Console.WriteLine("                        providers on the system");
            Console.WriteLine();
            Console.WriteLine("Disk Management Options:");
            Console.WriteLine("  --relabel             Update the volume label on existing partitions to match");
            Console.WriteLine("                        the IQN of the volume");
            Console.WriteLine("  --force_mountpoints   Remove automount drive letters and remount with mount point");
            Console.WriteLine("  --force_unmount       Forcibly unmount volumes before logging out of targets");
            Console.WriteLine();
            Console.WriteLine("Display Options:");
            Console.WriteLine("  --batch               Minimize the output (useful when being wrapped in a script)");
            Console.WriteLine("  --json                Format output as JSON (useful when being wrapped in a script)");
            Console.WriteLine();
            Console.WriteLine("Connection Parameters:");
            Console.WriteLine("  --client_ip           The IP address (or hostname if DNS is working) of the system");
            Console.WriteLine("                        to execute the verb on.");
            Console.WriteLine("  --username            The username to use on the remote system. If omitted the");
            Console.WriteLine("                        current user context is used.");
            Console.WriteLine("  --password            The password to use on the remote system. If omitted the");
            Console.WriteLine("                        current user context is used.");
            Console.WriteLine();
            Console.WriteLine("Omit the client_ip, username, password arguments to connect to the local machine.");
            Console.WriteLine("Currently remote connections only work between domain-joined machines.");
        }

        static bool ValidateArguments(CommandLineArguments Args)
        {
            List<string> known_args = new List<string>() 
            {
                "help",
                "h",
                "?",
                "debug",
                "client_ip",
                "username",
                "password",
                "add_portal",
                "remove_portal",
                "refresh_targets",
                "list_portals",
                "list_targets",
                "login_targets",
                "logout_targets",
                "list_disks",
                "online_disks",
                "setup_disks",
                "format_disks",
                "unmount_disks",
                "show_initiatorname",
                "set_initiatorname",
                "default_initiatorname",
                "clean",
                "portal_address",
                "chap_user",
                "chap_secret",
                "persistent",
                "name",
                "force_mountpoints",
                "relabel",
                "force_unmount",
                "dump_disk_info",
                "dump_vds_prov_info",
                "wait_for_debug",
                "batch",
                "list_sessions",
                "include_boot_vol",
                "json",
                "show_wwpns",
                "show_hbas",
            };

            // Check for extra/misspelled args
            bool error = false;
            foreach (string arg in Args.GetKeys())
            {
                if (!known_args.Contains(arg))
                {
                    Console.WriteLine("Unknown argument '" + arg + "'");
                    error = true;
                }
            }
            if (error) return false;

            // Check for required argument combinations
            if (Args["add_portal"] != null)
            {
                if (CheckRequiredArgsWithValues(Args, new List<string>() { "portal_address" }))
                {
                    if (Args["chap_user"] != null)
                    {
                        return CheckRequiredArgsWithValues(Args, new List<string>() { "chap_secret" });
                    }
                    if (Args["chap_secret"] != null)
                    {
                        return CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user" });
                    }
                }
                else
                {
                    return false;
                }
                return true;
            }
            else if (Args["remove_portal"] != null)
            {
                return CheckRequiredArgsWithValues(Args, new List<string>() { "portal_address" });
            }
            //else if (Args["refresh_targets"] != null) { }
            //else if (Args["list_portals"] != null) { }
            //else if (Args["login_targets"] != null) { }
            //else if (Args["logout_targets"] != null) { }
            //else if (Args["list_disks"] != null) { }
            //else if (Args["setup_disks"] != null) { }
            //else if (Args["get_initiatorname"] != null) { }
            else if (Args["set_initiatorname"] != null)
            {
                return CheckRequiredArgsWithValues(Args, new List<string>() { "name" });
            }
            //else if (Args["default_initiatorname"] != null) { }
            //else if (Args["clean"] != null) { }

            // Check for valid input
            if (Args["portal_address"] != null)
            {
                try
                {
                    System.Net.IPAddress.Parse(Args["portal_address"]);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Invalid portal_address");
                    return false;
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("Invalid portal_address");
                    return false;
                }
            }
            if (Args["wait_for_debug"] != null)
            {
                try
                {
                    int i = int.Parse(Args["wait_for_debug"]);
                    if (i <= 0)
                        throw new FormatException();
                }
                catch (FormatException)
                {
                    Console.WriteLine("wait_for_debug must be a positive integer");
                    return false;
                }
            }
            if (Args["username"] != null)
            {
                return CheckRequiredArgsWithValues(Args, new List<string>() { "password" });
            }
            if (Args["password"] != null)
            {
                return CheckRequiredArgsWithValues(Args, new List<string>() { "username" });
            }
            return true;
        }

        static bool CheckRequiredArgsWithValues(CommandLineArguments pArgs, List<string> pRequiredArgs)
        {
            bool valid = true;
            foreach (string ra in pRequiredArgs)
            {
                if (String.IsNullOrEmpty(pArgs[ra]))
                {
                    Console.WriteLine("Missing " + ra);
                    valid = false;
                }
            }
            return valid;
        }


    
    
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
                if (Logger.BatchMode)
                    Console.WriteLine(e.ExceptionObject.ToString());
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

            // CHAP info, if it was specified
            string arg_chap_user = Args["chap_user"];
            string arg_chap_init_secret = Args["init_secret"];
            if (arg_chap_init_secret == null)
                arg_chap_init_secret = Args["chap_secret"];
            string arg_chap_targ_secret = Args["targ_secret"];

            // Portal list, if it was specified
            List<string> arg_portal_list = null;
            if (Args["portal_address"] != null)
            {
                arg_portal_list = new List<string>(
                    Args["portal_address"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
            }

            // Target list, if it was specified
            List<string> arg_target_iqns = null;
            if (Args["target_iqn"] != null)
            {
                arg_target_iqns = new List<string>(
                    Args["target_iqn"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
                arg_target_iqns.ForEach(x => x.Trim());
            }

            // Device list, if it was specified
            List<string> arg_device_list = null;
            if (Args["devices"] != null)
            {
                arg_device_list = new List<string>(
                    Args["devices"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
                arg_device_list.ForEach(x => x.Trim());
            }

            //
            // Execute the verb the user requested
            //

            if (Args["add_portal"] != null)
            {
                try
                {
                    if (arg_chap_user != null && arg_chap_init_secret != null)
                        Logger.Info("Adding portal '" + arg_portal_list[0] + "' with CHAP user '" + arg_chap_user + "' and secret '" + arg_chap_init_secret + "'");
                    else
                        Logger.Info("Adding portal '" + arg_portal_list[0] + "'");

                    msinit.AddTargetPortal(PortalAddress: arg_portal_list[0], ChapUsername: arg_chap_user, ChapInitSecret: arg_chap_init_secret, ChapTargSecret: arg_chap_targ_secret);
                    
                    Logger.Info("Successfully added portal.");
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
                        if (batch || json)
                            Console.Error.WriteLine("Add portal failed: " + e.Message);
                        Environment.Exit(EXIT_FAIL);
                    }
                }
            }
            else if (Args["remove_portal"] != null)
            {
                if (arg_portal_list == null || arg_portal_list.Count <= 0)
                {
                    Logger.Error("Either specify a portal_address or use clear_portals to remove all");
                    if (batch || json)
                        Console.Error.WriteLine("Either specify a portal_address or use clear_portals to remove all");
                    Environment.Exit(EXIT_FAIL);
                }
                Logger.Info("Removing target portals [" + String.Join(",", arg_portal_list.ToArray()) + "]");

                try
                {
                    msinit.RemoveIscsiTargetPortals(arg_portal_list);
                    Logger.Info("Successfully removed portals");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Remove portal failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Remove portal failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["clear_portals"] != null)
            {
                Logger.Info("Removing all target portals");
                try
                {
                    msinit.RemoveIscsiTargetPortals();
                    Logger.Info("Successfully removed portals");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Remove portal failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Remove portal failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_portals"] != null)
            {
                List<MicrosoftInitiator.IscsiPortalInfo> portal_info = null;
                try
                {
                    portal_info = msinit.ListIscsiTargetPortals();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("List portals failed: " + e.Message);
                    if (batch || json)
                        Console.Error.WriteLine("Listing portals failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (var portal in portal_info)
                {
                    Logger.Info(portal.ToString());

                    if (batch)
                        Console.WriteLine(portal.ToString());
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(portal_info, Newtonsoft.Json.Formatting.Indented));
                Environment.Exit(EXIT_SUCCESS);
            }
            else if (Args["refresh_targets"] != null)
            {
                try
                {
                    Logger.Info("Refreshing target list...");
                    msinit.RefreshIscsiTargetPortals(arg_portal_list);
                    Logger.Info("Successfully refreshed targets.");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Refresh failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Refresh targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_targets"] != null)
            {
                bool include_boot = false;
                if (Args["include_boot_vol"] != null)
                    include_boot = true;

                List<MicrosoftInitiator.IscsiTargetInfo> target_list = new List<MicrosoftInitiator.IscsiTargetInfo>();
                try
                {
                    target_list = msinit.ListIscsiTargets(PortalAddressList: arg_portal_list, IncludeBootVolume: include_boot);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Listing targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.IscsiTargetInfo target in target_list)
                {
                    StringBuilder display_str = new StringBuilder();
                    display_str.Append("TargetPortal: " + target.TargetPortal);
                    display_str.Append(", TargetIqn: " + target.TargetIqn);
                    if (target.IsLoggedIn)
                        display_str.Append(" (LOGGED IN)");
                    else
                        display_str.Append(" (NOT LOGGED IN)");
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
                bool include_boot = false;
                if (Args["include_boot_vol"] != null)
                    include_boot = true;

                List<MicrosoftInitiator.IscsiSessionInfo> session_list = new List<MicrosoftInitiator.IscsiSessionInfo>();
                try
                {
                    session_list = msinit.ListIscsiSessions(PortalAddressList: arg_portal_list, IncludeBootVolume: include_boot);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing sessions failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Listing sessions failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.IscsiSessionInfo session in session_list)
                {
                    Logger.Info("SessionID: " + session.SessionId + ", TargetIQN: " + session.TargetIqn + ", InitiatorIP: " + session.InitiatorAddress + ", TargetIP: " + session.TargetAddress);
                    if (batch)
                        Console.WriteLine("SessionID: " + session.SessionId + ", TargetIQN: " + session.TargetIqn + ", InitiatorIP: " + session.InitiatorAddress + ", TargetIP: " + session.TargetAddress);
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

                string statement = "Logging in to";
                if (Args["target_iqn"] != null)
                    statement += " specified";
                else
                    statement += " all";
                statement += " targets";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";
                if (arg_chap_user != null && arg_chap_init_secret != null)
                {
                    statement += " with CHAP user '" + arg_chap_user + "' and init secret '" + arg_chap_init_secret + "'";
                    if (arg_chap_targ_secret != null)
                        statement += " targ secret '" + arg_chap_targ_secret + "'";
                }

                try
                {
                    Logger.Info(statement);
                    int logged_in = msinit.LoginIscsiTargets(ChapUsername: arg_chap_user, ChapInitSecret: arg_chap_init_secret, ChapTargSecret: arg_chap_targ_secret, PortalAddressList: arg_portal_list, TargetsToLogin: arg_target_iqns, MakePersistent: persistent);

                    if (logged_in > 0)
                    {
                        Logger.Info("Onlining/signaturing all disks");
                        msinit.OnlineDisks();
                    }
                    Logger.Info("Successfully logged in to targets");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Login targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Login targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["qlogin"] != null)
            {
                string statement = "";

                // Remove the portal if it already exists
                try
                {
                    msinit.RemoveIscsiTargetPortals(new List<string>() { arg_portal_list[0] });
                }
                catch (MicrosoftInitiator.InitiatorException)
                { }

                // Add the portal
                statement = "Adding portal '" + arg_portal_list[0] + "'";
                if (arg_chap_user != null && arg_chap_init_secret != null)
                {
                    statement += " with CHAP user '" + arg_chap_user + "' and init secret '" + arg_chap_init_secret + "'";
                    if (arg_chap_targ_secret != null)
                        statement += " targ secret '" + arg_chap_targ_secret + "'";
                }
                Logger.Info(statement);
                try
                {
                    msinit.AddTargetPortal(PortalAddress: arg_portal_list[0], ChapUsername: arg_chap_user, ChapInitSecret: arg_chap_init_secret, ChapTargSecret: arg_chap_targ_secret);
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
                        if (batch || json)
                            Console.Error.WriteLine("Add portal failed: " + e.Message);
                        Environment.Exit(EXIT_FAIL);
                    }
                }

                // Refresh the target list
                Logger.Info("Refreshing target list on all portals...");
                try
                {
                    msinit.RefreshIscsiTargetPortals();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Refresh failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Refresh targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                // Log in to targets
                bool persistent = false;
                if (Args["persistent"] != null)
                    persistent = true;

                statement = "Logging in to";
                if (Args["target_iqn"] != null)
                    statement += " specified";
                else
                    statement += " all";
                statement += " targets on portal " + Args["portal_address"];
                if (arg_chap_user != null && arg_chap_init_secret != null)
                {
                    statement += " with CHAP user '" + arg_chap_user + "' and init secret '" + arg_chap_init_secret + "'";
                    if (arg_chap_targ_secret != null)
                        statement += " targ secret '" + arg_chap_targ_secret + "'";
                }
                Logger.Info(statement);
                try
                {
                    int logged_in = msinit.LoginIscsiTargets(ChapUsername: arg_chap_user, ChapInitSecret: arg_chap_init_secret, ChapTargSecret: arg_chap_targ_secret, PortalAddressList: new List<string>() { arg_portal_list[0] }, TargetsToLogin: arg_target_iqns, MakePersistent: persistent);

                    if (logged_in > 0)
                    {
                        Logger.Info("Onlining/signaturing all disks");
                        msinit.OnlineDisks();
                    }
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Login targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Login targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                Logger.Info("Successfully logged in to targets");
            }
            else if (Args["logout_targets"] != null)
            {
                bool remove_persistent = false;
                if (Args["persistent"] != null)
                    remove_persistent = true;
                bool force = false;
                if (Args["force_unmount"] != null)
                    force = true;

                string statement = "";
                if (force)
                    statement += "Forcably logging";
                else
                    statement += "Logging";
                statement += " out of";
                if (Args["target_iqn"] != null)
                    statement += " specified";
                else
                    statement += " all";
                statement += " active targets";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";

                Logger.Info(statement);
                try
                {
                    if (force)
                        msinit.UnmountAndOfflineDisks(PortalAddressList: arg_portal_list, TargetList: arg_target_iqns, ForceUnmount: true);
                    msinit.LogoutIscsiTargets(PortalAddressList: arg_portal_list, TargetsToLogout: arg_target_iqns, RemovePersistent: remove_persistent);

                    Logger.Info("Successfully logged out of targets.");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Logout targets failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Logout targets failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_disks"] != null)
            {
                List<MicrosoftInitiator.DiskInfo> disk_list = new List<MicrosoftInitiator.DiskInfo>();
                try
                {
                    disk_list = msinit.ListDiskInfo(PortalAddressList: arg_portal_list);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Listing disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach (MicrosoftInitiator.DiskInfo disk in disk_list)
                {
                    string output = disk.LegacyDeviceName;
                    if (disk.TargetType.ToLower() == "iscsi")
                    {
                        output += " (iSCSI) " + disk.IscsiTargetName + ", Portal: " + disk.IscsiPortalAddress;
                    }
                    else
                    {
                        output += " (FC) ";
                    }
                    output += ", SectorSize: " + disk.SectorSize;
                    if (disk.Online)
                        output += ", Flags: Online";
                    else
                        output += ", Flags: Offline";
                    if (disk.Readonly)
                        output += "/RO";
                    else
                        output += "/RW";
                    output += ", MountPoint: " + disk.MountPoint;

                    Logger.Info(output);

                    if (batch)
                    {
                        output = "DeviceName: " + disk.LegacyDeviceName + ", TargetType: " + disk.TargetType;
                        if (disk.TargetType.ToLower() == "iscsi")
                            output += ", TargetName: " + disk.IscsiTargetName + ", Portal: " + disk.IscsiPortalAddress;
                        output += ", SectorSize: " + disk.SectorSize;
                        if (disk.Online)
                            output += ", Flags: Online";
                        else
                            output += ", Flags: Offline";
                        if (disk.Readonly)
                            output += "/RO";
                        else
                            output += "/RW";
                        output += ", MountPoint: " + disk.MountPoint;
                        Console.WriteLine(output);
                    }
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(disk_list, Newtonsoft.Json.Formatting.Indented));
            }
            else if (Args["rescan_disks"] != null)
            {
                Logger.Info("Rescanning disks/paths...");
                try
                {
                    msinit.RescanDisks();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Rescanning disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Rescanning disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["online_disks"] != null)
            {
                string statement = "Online/signature";
                if ((arg_device_list != null && arg_device_list.Count > 0) || (arg_target_iqns != null && arg_target_iqns.Count > 0))
                    statement += " specified";
                else
                    statement += " all";
                statement += " disk devices";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";
                Logger.Info(statement);

                try
                {
                    msinit.OnlineDisks(DeviceList: arg_device_list, PortalAddressList: arg_portal_list, TargetList: arg_target_iqns);
                    Logger.Info("Successfully onlined disks");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Onlining disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Onlining disks failed: " + e.Message);
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

                string statement = "Partition/format/mounting";
                if ((arg_device_list != null && arg_device_list.Count > 0) || (arg_target_iqns != null && arg_target_iqns.Count > 0))
                    statement += " specified";
                else
                    statement += " all";
                statement += " disk devices";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";
                Logger.Info(statement);
                
                try
                {
                    msinit.PartitionAndFormatDisks(DeviceList: arg_device_list, PortalAddressList: arg_portal_list, TargetList: arg_target_iqns, RelabelVolumes: relabel);
                    msinit.MountpointDisks(DeviceList: arg_device_list, PortalAddressList: arg_portal_list, TargetList: arg_target_iqns, ForceMountPoints: force_mountpoints);
                    Logger.Info("Successfully set up disks");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setup disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Setup disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["format_disks"] != null)
            {
                bool relabel = false;
                if (Args["relabel"] != null)
                    relabel = true;

                string statement = "Partition/formatting";
                if ((arg_device_list != null && arg_device_list.Count > 0) || (arg_target_iqns != null && arg_target_iqns.Count > 0))
                    statement += " specified";
                else
                    statement += " all";
                statement += " disk devices";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";
                Logger.Info(statement);

                try
                {
                    msinit.PartitionAndFormatDisks(DeviceList: arg_device_list, PortalAddressList: arg_portal_list, TargetList: arg_target_iqns, RelabelVolumes: relabel);
                    Logger.Info("Successfully formatted disks");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setup disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Format disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["unmount_disks"] != null)
            {
                string statement = "Removing mountpoints from";
                if ((arg_device_list != null && arg_device_list.Count > 0) || (arg_target_iqns != null && arg_target_iqns.Count > 0))
                    statement += " specified";
                else
                    statement += " all";
                statement += " disk devices";
                if (arg_portal_list != null && arg_portal_list.Count > 0)
                    statement += " on portals [" + String.Join(",", arg_portal_list.ToArray()) + "]";
                Logger.Info(statement);

                try
                {
                    msinit.RemoveMountpoints(DeviceList: arg_device_list, PortalAddressList: arg_portal_list, TargetList: arg_target_iqns);
                    Logger.Info("Successfully removed mounts");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Unmount disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Unmount disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["show_initiatorname"] != null || Args["get_initiatorname"] != null)
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
                    if (batch || json)
                        Console.Error.WriteLine("Querying initiator name failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["set_initiatorname"] != null)
            {
                try
                {
                    msinit.SetIscsiInitiatorName(Args["name"]);
                    Logger.Info("Successfully set initiator name");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setting initiator name failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Setting initiator name failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["default_initiatorname"] != null)
            {
                try
                {
                    msinit.SetIscsiInitiatorName(null);
                    Logger.Info("Successfully set initiator name");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setting initiator name failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Setting initiator name failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["clean"] != null || Args["clean_iscsi"] != null)
            {
                try
                {
                    Logger.Info("Clearing target secret");
                    msinit.ClearIscsiChapTargetSecret();
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Logging out of all active targets");
                    msinit.LogoutIscsiTargets(RemovePersistent: true);
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Removing all target portals");
                    msinit.RemoveIscsiTargetPortals();
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Clearing target list");
                    msinit.RefreshIscsiTargetPortals();
                }
                catch (MicrosoftInitiator.InitiatorException) { }

                try
                {
                    Logger.Info("Removing persistent logins");
                    msinit.ClearIscsiPersistentLogins();
                }
                catch (MicrosoftInitiator.InitiatorException) { }
                
                Logger.Info("Successfully cleaned iSCSI initiator");
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
                    msinit.DebugShowAllVdsProviders();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Getting VDS info failed: " + e.Message);
                    LogExceptionDetail(e);
                    Environment.Exit(EXIT_FAIL);
                }

            }
            else if (Args["show_wwpns"] != null || Args["list_wwpns"] != null)
            {
                List<string> wwns = new List<string>();
                try
                {
                    wwns = msinit.ListWwpns();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Querying WWNs failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Querying WWNs failed: " + e.Message);
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
            else if (Args["show_hbas"] != null || Args["list_hbas"] != null)
            {
                List<MicrosoftInitiator.FcHbaInfo> hbas = new List<MicrosoftInitiator.FcHbaInfo>();
                try
                {
                    hbas = msinit.ListFcHbaInfo();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Querying HBA info failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Querying HBAs failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                Logger.Info("Found " + hbas.Count + " HBAs");
                foreach (var h in hbas)
                {
                    Logger.Info("");
                    Logger.Info("  Model:           " + h.Model);
                    Logger.Info("  Description:       " + h.Description);
                    Logger.Info("  WWN:               " + h.WWPN);
                    Logger.Info("  Speed:             " + h.Speed);
                    Logger.Info("  PortState:         " + h.PortState);
                    Logger.Info("  DriverVersion:     " + h.DriverVersion);
                    Logger.Info("  FirmwareVersion:   " + h.FirmwareVersion);
                    Logger.Info("  UniqueLUNCount:    " + h.UniqueLunCount);
                    Logger.Info("  TotalLunPathCount: " + h.TotalLunPathCount);
                    Logger.Info("  Targets: ");
                    foreach (string targ in h.TargetWWPNs)
                    {
                        Logger.Info("    " + targ);
                    }
                }
                if (batch)
                {
                    int index = 0;
                    foreach (var h in hbas)
                    {
                        Console.WriteLine("HBA " + index);
                        Console.WriteLine("  Model:             " + h.Model);
                        Console.WriteLine("  Description:       " + h.Description);
                        Console.WriteLine("  WWN:               " + h.WWPN);
                        Console.WriteLine("  Speed:             " + h.Speed);
                        Console.WriteLine("  PortState:         " + h.PortState);
                        Console.WriteLine("  DriverVersion:     " + h.DriverVersion);
                        Console.WriteLine("  FirmwareVersion:   " + h.FirmwareVersion);
                        Console.WriteLine("  UniqueLUNCount:    " + h.UniqueLunCount);
                        Console.WriteLine("  TotalLunPathCount: " + h.TotalLunPathCount);
                        Console.WriteLine("  Targets: ");
                        foreach (string targ in h.TargetWWPNs)
                        {
                            Console.WriteLine("    " + targ);
                        }
                        index++;
                    }
                }
                else if (json)
                {
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(hbas, Newtonsoft.Json.Formatting.Indented));
                }
            }
            else if (Args["list_paths"] != null)
            {
                List<MicrosoftInitiator.MpioDiskInfo> disk_list = new List<MicrosoftInitiator.MpioDiskInfo>();
                try
                {
                    disk_list = msinit.ListMpioDiskInfo();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Querying path info failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Querying path info failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                foreach(var disk in disk_list)
                {
                    string output = disk.LegacyDeviceName;
                    if (disk.TargetType.ToLower() == "iscsi")
                    {
                        output += " (iSCSI) " + disk.IscsiTargetName + ", Portal: " + disk.IscsiPortalAddress;
                    }
                    else
                    {
                        output += " (FC) ";
                    }
                    output += ", SectorSize: " + disk.SectorSize;
                    if (disk.Online)
                        output += ", Flags: Online";
                    else
                        output += ", Flags: Offline";
                    if (disk.Readonly)
                        output += "/RO";
                    else
                        output += "/RW";
                    output += ", MountPoint: " + disk.MountPoint;

                    Logger.Info(output);

                    output = "    NumberOfPaths: " + disk.DSM_Paths.Count + ", FailedPaths: " + disk.FailedPathCount + ", LBPolicy: " + disk.LoadBalancePolicy + ", SupportedLBPolicy: [" + String.Join("|", disk.Supported_LB_Policies.ToArray()) + "]";
                    Logger.Info(output);

                    if (batch)
                    {
                        output = "DeviceName: " + disk.LegacyDeviceName + ", TargetType: " + disk.TargetType;
                        if (disk.TargetType.ToLower() == "iscsi")
                            output += ", TargetName: " + disk.IscsiTargetName + ", Portal: " + disk.IscsiPortalAddress;
                        output += ", SectorSize: " + disk.SectorSize;
                        if (disk.Online)
                            output += ", Flags: Online";
                        else
                            output += ", Flags: Offline";
                        if (disk.Readonly)
                            output += "/RO";
                        else
                            output += "/RW";
                        output += ", MountPoint: " + disk.MountPoint;
                        Console.WriteLine(output);
                        output = "    NumberOfPaths: " + disk.DSM_Paths.Count + ", FailedPaths: " + disk.FailedPathCount + ", LBPolicy: " + disk.LoadBalancePolicy + ", SupportedLBPolicy: [" + String.Join("|", disk.Supported_LB_Policies.ToArray()) + "]";
                        Console.WriteLine(output);
                    }
                }
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(disk_list, Newtonsoft.Json.Formatting.Indented));
            }
            else if (Args["enable_mpio"] != null)
            {
                bool reboot_required = false;
                try
                {
                    reboot_required = msinit.EnableMpio(Args["device_string"]);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Enabling MPIO failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Enabling MPIO failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
                Logger.Info("MPIO is now enabled");
                if (reboot_required)
                    Logger.Info("You must reboot the system for the changes to take affect");
    
                if (batch)
                    Console.WriteLine("RebootRequired: " + reboot_required.ToString());
                else if (json)
                {
                    Console.WriteLine("{\n    \"RebootRequired\": " + reboot_required + "\n}");
                }
            }
            else if (Args["disable_mpio"] != null)
            {
                bool reboot_required = false;
                try
                {
                    reboot_required = msinit.DisableMpio(Args["device_string"]);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Disabling MPIO failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Disabling MPIO failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
                Logger.Info("MPIO is now disabled");
                if (reboot_required)
                    Logger.Info("You must reboot the system for the changes to take affect");

                if (batch)
                    Console.WriteLine("RebootRequired: " + reboot_required.ToString());
                else if (json)
                {
                    Console.WriteLine("{\n    \"RebootRequired\": " + reboot_required + "\n}");
                }
            }
            else if (Args["set_lb_policy"] != null)
            {
                MicrosoftInitiator.DSM_LB_POLICY lb_policy = Args["policy"].GetEnumValueFromDescription<MicrosoftInitiator.DSM_LB_POLICY>();
                try
                {
                    msinit.SetMpioLoadBalancePolicy(lb_policy);
                    Logger.Info("Successfully set load balance policy");
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Setting LB policy failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Setting LB policy failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
            }
            else if (Args["list_lb_policy"] != null)
            {
                List<string> lb_policies = new List<string>();
                try
                {
                    lb_policies = msinit.ListMpioLoadBalancePolicies();
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Querying LB policies failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Querying LB policies failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }
                Logger.Info("Available policies: " + String.Join(", ", lb_policies.ToArray()));
                Logger.Info("Use --list_paths to see the supported policies for a given volume");
                if (batch)
                    Console.WriteLine("Policies: [" + String.Join(",", lb_policies.ToArray()) + "]");
                if (json)
                    Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(lb_policies, Newtonsoft.Json.Formatting.Indented));
            }
            else if (Args["vdbench_devices"] != null)
            {
                string host_number = "1";
                if (Args["vdbench_host"] != null)
                    host_number = Args["vdbench_host"];

                List<MicrosoftInitiator.DiskInfo> disk_list = new List<MicrosoftInitiator.DiskInfo>();
                try
                {
                    disk_list = msinit.ListDiskInfo(PortalAddressList: arg_portal_list);
                }
                catch (MicrosoftInitiator.InitiatorException e)
                {
                    Logger.Error("Listing disks failed: " + e.Message);
                    LogExceptionDetail(e);
                    if (batch || json)
                        Console.Error.WriteLine("Listing disks failed: " + e.Message);
                    Environment.Exit(EXIT_FAIL);
                }

                int disk_index = 1;
                foreach (MicrosoftInitiator.DiskInfo disk in disk_list)
                {
                    Console.WriteLine("sd=sd" + host_number + "_" + disk_index + ",host=hd" + host_number + ",lun=" + disk.LegacyDeviceName + ",openflags=directio,size=" + disk.Size);
                    disk_index++;
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
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("iSCSI Verbs:");
            Console.WriteLine("  --get_initiatorname   Display the current initiator IQN");
            Console.WriteLine("  --set_initiatorname   Change the current initiator IQN");
            Console.WriteLine("  --default_initiatorname   Change the current initiator IQN to the default");
            Console.WriteLine("                        value (based on hostname)");
            Console.WriteLine("  --qlogin              Add portal, discover targets, login targets in a single");
            Console.WriteLine("                        single step. Requires portal_address, and requires");
            Console.WriteLine("                        chap_use, init_secret/targ_secret if using CHAP.");
            Console.WriteLine("                        Optionally include target_iqn");
            Console.WriteLine("  --add_portal          Add a target discovery portal to the initiator. Requires");
            Console.WriteLine("                        portal_address, and requires chap_user, init_secret,");
            Console.WriteLine("                        targ_secret using CHAP");
            Console.WriteLine("  --remove_portal       Remove a discovery portal from the initiator. Requires");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --clear_portals       Remove all discovery portals from the initiator");
            Console.WriteLine("  --list_portals        Display a list of the configured target portals");
            Console.WriteLine("  --list_targets        Display a list of discovered targets. Optionally");
            Console.WriteLine("                        include portal_address");
            Console.WriteLine("  --list_sessions       Display a list of sessions. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --refresh_targets     Refresh the list of discovered targets. Optionally");
            Console.WriteLine("                        include portal_address");
            Console.WriteLine("  --login_targets       Log in to discovered targets. Requires chap_user,");
            Console.WriteLine("                        init_secret/targ_secret if using CHAP. Optionally");
            Console.WriteLine("                        include portal_address, target_iqn");
            Console.WriteLine("  --logout_targets      Log out of connected targets. Optionally include");
            Console.WriteLine("                        portal_address, target_iqn");
            Console.WriteLine("  --clear_targ_secret   Clear the CHAP target secret");
            Console.WriteLine("  --clean_iscsi         Log out of sessions, remove all persistent info and");
            Console.WriteLine("                        return the iSCISI initiator to a pristine state");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("iSCSI Options:");
            Console.WriteLine("  --portal_address      One or more target portal IP addresses to use for the");
            Console.WriteLine("                        operation");
            Console.WriteLine("  --target_iqn          One or more target IQNs to use for the operation");
            Console.WriteLine("  --chap_user           The CHAP username to use for the operation");
            Console.WriteLine("  --init_secret         The CHAP initiator secret to use for the operation");
            Console.WriteLine("  --targ_secret         The CHAP target secret to use for the operation");
            Console.WriteLine("  --persistent          Create a persistent login (reconnect after reboot) to");
            Console.WriteLine("                        the targets");
            Console.WriteLine("  --name                The initiator name (IQN)");
            Console.WriteLine("  --include_boot_vol    Include the iSCSI boot volume in listing verbs");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("Fibre Channel Verbs:");
            Console.WriteLine("  --list_wwpns          Display the current FC initiator WWPNs");
            Console.WriteLine("  --list_hbas           Display the installed FC HBA info");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("MPIO Verbs:");
            Console.WriteLine("  --enable_mpio         Enable MPIO and add a device string so that multipath");
            Console.WriteLine("                        volumes are claimed by the MS DSM (usually requires");
            Console.WriteLine("                        a reboot). Requires device_string");
            Console.WriteLine("  --disable_mpio        Disable MPIO (usually requires a reboot). Requires");
            Console.WriteLine("                        device_string");
            Console.WriteLine("  --list_lb_policy      List the available MPIO load balance policies. Use");
            Console.WriteLine("                        list_paths to see supported policies for particular");
            Console.WriteLine("                        volumes");
            Console.WriteLine("  --set_lb_policy       Set the MPIO load balancing policy for MPIO volumes.");
            Console.WriteLine("                        Requires policy, optionally include devices");
            Console.WriteLine("  --list_paths          Display the list of volumes and their paths");
            Console.WriteLine();
            Console.WriteLine("MPIO Options:");
            Console.WriteLine("  --policy              The load balance policy to set");
            Console.WriteLine("  --devices             Only operate on this list of devices (device names e.g.");
            Console.WriteLine("                        \"\\\\.\\PhysicalDrive2, \\\\.\\PhysicalDrive3\"");
            Console.WriteLine("  --device_string       The device string to pass to MPIO to claim");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("Disk Management Verbs:");
            Console.WriteLine("  --list_disks          Display a list of disk devices and their corresponding");
            Console.WriteLine("                        targets and mount points. Optionally include");
            Console.WriteLine("                        portal_address");
            Console.WriteLine("  --rescan_disks        Rescan for added/removed disks and paths");
            Console.WriteLine("  --online_disks        Set disk devices online and read-write.");
            Console.WriteLine("                        Optionally include devices");
            Console.WriteLine("  --format_disks        Create partitions and format the devices from logged");
            Console.WriteLine("                        in targets. Optionally include portal_address,");
            Console.WriteLine("                        devices, relabel, force_mountpoints");
            Console.WriteLine("  --setup_disks         Create partitions, format and mount the devices from");
            Console.WriteLine("                        logged in targets. Optionally include portal_address,");
            Console.WriteLine("                        devices, relabel, force_mountpoints");
            Console.WriteLine("  --unmount_disks       Remove mount points and drive letters from logged in");
            Console.WriteLine("                        targets. Optionally include devices");
            Console.WriteLine("  --dump_disk_info      Print out as much information as possible about the");
            Console.WriteLine("                        connected disk devices on the system");
            Console.WriteLine("  --dump_vds_prov_info  Print out as much information as possible about the VDS");
            Console.WriteLine("                        providers on the system");
            Console.WriteLine("  --vdbench_devices     Print out sd lines for pasting into a vdbench config");
            Console.WriteLine("                        file");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("Disk Management Options:");
            Console.WriteLine("  --devices             Only operate on this list of devices (device names e.g.");
            Console.WriteLine("                        \"\\\\.\\PhysicalDrive2, \\\\.\\PhysicalDrive3\"");
            Console.WriteLine("  --relabel             Update the volume label on existing partitions to match");
            Console.WriteLine("                        the IQN of the volume");
            Console.WriteLine("  --force_mountpoints   Remove automount drive letters and remount with mount");
            Console.WriteLine("                        points");
            Console.WriteLine("  --force_unmount       Forcibly unmount volumes before logging out of targets");
            Console.WriteLine("  --vdbench_host        Host number to use for vdbench sd devices");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("Display Options:");
            Console.WriteLine("  --batch               Minimize the output (useful when being wrapped in a");
            Console.WriteLine("                        script)");
            Console.WriteLine("  --json                Format output as JSON (useful when being wrapped in a");
            Console.WriteLine("                        script)");
            Console.WriteLine();
            //                 0        1         2         3         4         5         6         7         8
            //                 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            Console.WriteLine("Connection Parameters:");
            Console.WriteLine("  --client_ip           The IP address (or hostname if DNS is working) of the");
            Console.WriteLine("                        system to execute the verb on.");
            Console.WriteLine("  --username            The username to use on the remote system. If omitted the");
            Console.WriteLine("                        current user context is used.");
            Console.WriteLine("  --password            The password to use on the remote system. If omitted the");
            Console.WriteLine("                        current user context is used.");
            Console.WriteLine();
            Console.WriteLine("Omit the client_ip, username, password args to connect to the local machine.");
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
                "get_initiatorname",
                "show_initiatorname",
                "set_initiatorname",
                "default_initiatorname",
                "clean",
                "portal_address",
                "chap_user",
                "chap_secret",
                "init_secret",
                "targ_secret",
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
                "list_wwpns",
                "show_wwpns",
                "list_hbas",
                "show_hbas",
                "list_paths",
                "enable_mpio",
                "disable_mpio",
                "qlogin",
                "target_iqn",
                "allow_invalid_iqn",
                "set_lb_policy",
                "policy",
                "list_lb_policy",
                "clear_targ_secret",
                "clear_portals",
                "vdbench_devices",
                "vdbench_host",
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

            if (Args["target_iqn"] != null)
            {
                var target_list = new List<string>(
                    Args["target_iqn"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
                target_list.ForEach(x => x.Trim());
                if (target_list.Count <= 0)
                {
                    Console.WriteLine("Please include a list of IQNs when using target_list");
                    return false;
                }
            }

            // Check for required argument combinations
            if (Args["add_portal"] != null)
            {
                if (CheckRequiredArgsWithValues(Args, new List<string>() { "portal_address" }))
                {
                    if (Args["chap_user"] != null)
                    {
                        if (Args["chap_secret"] == null && Args["init_secret"] == null)
                        {
                            Console.Error.WriteLine("Missing init_secret");
                            return false;
                        }
                    }
                    if (Args["chap_secret"] != null || Args["init_secret"] != null)
                    {
                        if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user" }))
                            return false;
                    }
                    if (Args["targ_secret"] != null)
                    {
                        if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user", "init_secret" }))
                            return false;
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
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "portal_address" }))
                    return false;
            }
            else if (Args["login_targets"] != null)
            {
                if (Args["chap_user"] != null)
                {
                    if (Args["chap_secret"] == null && Args["init_secret"] == null)
                    {
                        Console.Error.WriteLine("Missing init_secret");
                        return false;
                    }
                }
                if (Args["chap_secret"] != null || Args["init_secret"] != null)
                {
                    if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user" }))
                        return false;
                }
                if (Args["targ_secret"] != null)
                {
                    if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user", "init_secret" }))
                        return false;
                }
            }
            else if (Args["qlogin"] != null)
            {
                if (CheckRequiredArgsWithValues(Args, new List<string>() { "portal_address" }))
                {
                    if (Args["chap_user"] != null)
                    {
                        if (Args["chap_secret"] == null && Args["init_secret"] == null)
                        {
                            Console.Error.WriteLine("Missing init_secret");
                            return false;
                        }
                    }
                    if (Args["chap_secret"] != null)
                    {
                        if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user" }))
                            return false;
                    }
                    if (Args["init_secret"] != null)
                    {
                        if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user" }))
                            return false;
                    }
                    if (Args["targ_secret"] != null)
                    {
                        if (!CheckRequiredArgsWithValues(Args, new List<string>() { "chap_user", "init_secret" }))
                            return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else if (Args["set_initiatorname"] != null)
            {
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "name" }))
                    return false;
            }
            else if (Args["set_lb_policy"] != null)
            {
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "policy" }))
                    return false;
            }
            if (Args["username"] != null)
            {
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "password" }))
                    return false;
            }
            if (Args["password"] != null)
            {
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "username" }))
                    return false;
            }
            if (Args["enable_mpio"] != null || Args["disable_mpio"] != null)
            {
                if (!CheckRequiredArgsWithValues(Args, new List<string>() { "device_string" }))
                    return false;
            }

            // Check for valid input
            if (Args["portal_address"] != null)
            {
                List<string> arg_portal_list = new List<string>(
                    Args["portal_address"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
                if (arg_portal_list.Count <= 0)
                {
                    Console.Error.WriteLine("Invalid portal_address");
                    return false;
                }
                foreach (string portal in arg_portal_list)
                {
                    try
                    {
                        System.Net.IPAddress.Parse(portal);
                    }
                    catch (FormatException)
                    {
                        Console.Error.WriteLine("Invalid portal_address");
                        return false;
                    }
                    catch (ArgumentException)
                    {
                        Console.Error.WriteLine("Invalid portal_address");
                        return false;
                    }
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
                    Console.Error.WriteLine("wait_for_debug must be a positive integer");
                    return false;
                }
            }
            if (Args["chap_secret"] != null)
            {
                if (Args["chap_secret"].Length < 12 || Args["chap_secret"].Length > 16)
                {
                    Console.Error.WriteLine("CHAP initiator secret is invalid length");
                    return false;
                }
            }
            if (Args["init_secret"] != null)
            {
                if (Args["init_secret"].Length < 12 || Args["init_secret"].Length > 16)
                {
                    Console.Error.WriteLine("CHAP initiator secret is invalid length");
                    return false;
                }
            }
            if (Args["targ_secret"] != null)
            {
                if (Args["targ_secret"].Length < 12 || Args["targ_secret"].Length > 16)
                {
                    Console.Error.WriteLine("CHAP target secret is invalid length");
                    return false;
                }
                if (Args["targ_secret"].Length > 12)
                {
                    Console.Error.WriteLine("Max CHAP target secret length is 12 when IPsec is not used");
                    return false;
                }
            }
            if (Args["client_ip"] != null)
            {
                try
                {
                    System.Net.IPAddress.Parse(Args["client_ip"]);
                }
                catch (FormatException)
                {
                    Console.Error.WriteLine("Invalid client_ip");
                    return false;
                }
                catch (ArgumentException)
                {
                    Console.Error.WriteLine("Invalid client_ip");
                    return false;
                }
            }
            if (Args["name"] != null && Args["allow_invalid_iqn"] == null)
            {
                if (!Regex.IsMatch(Args["name"], @"^iqn.[0-9]{4}-[0-9]{2}.[a-z0-9\.\:-]+$"))
                {
                    Console.Error.WriteLine("Invalid IQN");
                    return false;
                }
            }
            if (Args["target_iqn"] != null)
            {
                List<string> target_list = new List<string>(
                    Args["target_iqn"].Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                );
                target_list.ForEach(x => x.Trim());

                if (target_list.Count <= 0)
                {
                    Console.Error.WriteLine("Invalid target_iqn");
                    return false;
                }

                if (Args["allow_invalid_iqn"] == null)
                {
                    foreach (var target_name in target_list)
                    {
                        if (!Regex.IsMatch(target_name, @"^iqn.[0-9]{4}-[0-9]{2}.[a-z0-9\.\:-]+$"))
                        {
                            Console.Error.WriteLine("Invalid target IQN");
                            return false;
                        }
                    }
                }
                if (Args["policy"] != null)
                {
                    try
                    {
                        Args["policy"].GetEnumValueFromDescription<MicrosoftInitiator.DSM_LB_POLICY>();
                    }
                    catch (ArgumentException)
                    {
                        return false;
                    }
                }
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
                    Console.Error.WriteLine("Missing " + ra);
                    valid = false;
                }

            }
            return valid;
        }


    
    
    }
}

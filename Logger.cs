using log4net;
using log4net.Repository.Hierarchy;
using log4net.Core;
using log4net.Appender;
using log4net.Layout;
using System.Diagnostics;
using System.Reflection;


namespace windiskhelper
{
    public class Logger
    {
        private const string LOG_PATTERN = "%date{yyy-MM-dd HH:mm:ss,fff}: %-6level %message%newline";
        private static ILog m_Log;

        public static bool BatchMode = false;

        static Logger()
        {
            InitLog();
        }

        private static void InitLog()
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();
            hierarchy.Root.Level = Level.All;

            PatternLayout patternLayout = new PatternLayout();
            patternLayout.ConversionPattern = LOG_PATTERN;
            patternLayout.ActivateOptions();

            // ColoredConsoleAppender - write to console with severity-colored messages
            ColoredConsoleAppender cca = new ColoredConsoleAppender();
            cca.Target = "Console.Error";
            cca.Name = "ConsoleLogger";
            cca.Layout = patternLayout;
            cca.Target = "Console.Out";

            ColoredConsoleAppender.LevelColors level = new ColoredConsoleAppender.LevelColors();
            level.Level = Level.Debug;
            level.ForeColor = ColoredConsoleAppender.Colors.White;
            cca.AddMapping(level);

            level = new ColoredConsoleAppender.LevelColors();
            level.Level = Level.Info;
            level.ForeColor = ColoredConsoleAppender.Colors.White | ColoredConsoleAppender.Colors.HighIntensity;
            cca.AddMapping(level);

            level = new ColoredConsoleAppender.LevelColors();
            level.Level = Level.Warn;
            level.ForeColor = ColoredConsoleAppender.Colors.Yellow | ColoredConsoleAppender.Colors.HighIntensity;
            cca.AddMapping(level);

            level = new ColoredConsoleAppender.LevelColors();
            level.Level = Level.Error;
            level.ForeColor = ColoredConsoleAppender.Colors.Red | ColoredConsoleAppender.Colors.HighIntensity;
            cca.AddMapping(level);

            cca.ActivateOptions();
            hierarchy.Root.AddAppender(cca);


            // RollingFileAppender - write to log file with rollover
            RollingFileAppender roller = new RollingFileAppender();
            roller.Layout = patternLayout;
            roller.AppendToFile = true;
            roller.RollingStyle = RollingFileAppender.RollingMode.Size;
            roller.ImmediateFlush = true;
            roller.MaxSizeRollBackups = 4;
            roller.MaximumFileSize = "100KB";
            roller.StaticLogFileName = true;
            roller.File = Assembly.GetExecutingAssembly().GetName().Name + ".log";
            roller.ActivateOptions();
            hierarchy.Root.AddAppender(roller);

            hierarchy.Configured = true;

            m_Log = LogManager.GetLogger(System.Reflection.Assembly.GetExecutingAssembly().FullName);

        }

        public static void EnableBatchMode()
        {
            //// Add a filter to only show ERROR and above on the console
            //Hierarchy hierarchy = LogManager.GetRepository() as Hierarchy;
            //ColoredConsoleAppender console = hierarchy.Root.GetAppender("ConsoleLogger") as ColoredConsoleAppender;
            //var filter = new log4net.Filter.LevelRangeFilter();
            //filter.LevelMin = Level.Error;
            //console.AddFilter(filter);

            // Turn off console logging completely by removing that appender
            Hierarchy hierarchy = LogManager.GetRepository() as Hierarchy;
            hierarchy.Root.RemoveAppender("ConsoleLogger");

            BatchMode = true;
        }

        public static void EnableConsoleDebug()
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();
            ColoredConsoleAppender console = hierarchy.Root.GetAppender("ConsoleLogger") as ColoredConsoleAppender;
            if (console != null)
            {
                console.Threshold = Level.Debug;
            }
        }
        public static void DisableConsoleDebug()
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();
            ColoredConsoleAppender console = hierarchy.Root.GetAppender("ConsoleLogger") as ColoredConsoleAppender;
            if (console != null)
            {
                console.Threshold = Level.Info;
            }
        }

        public static void Debug(string Message)
        {
            //string full_message = Message;
            //full_message = GetCaller() + " | " + full_message;
            //m_Log.Debug(full_message);
            m_Log.Debug(Message);
        }

        public static void Info(string Message)
        {
            //string full_message = Message;
            //full_message = GetCaller() + " | " + full_message;
            //m_Log.Info(full_message);
            m_Log.Info(Message);
        }

        public static void Warn(string Message)
        {
            //string full_message = Message;
            //full_message = GetCaller() + " | " + full_message;
            //m_Log.Warn(full_message);
            m_Log.Warn(Message);
        }

        public static void Error(string Message)
        {
            //string full_message = Message;
            //full_message = GetCaller() + " | " + full_message;
            //m_Log.Error(full_message);
            m_Log.Error(Message);
        }


        private static string GetCaller()
        {
            StackTrace callStack = new StackTrace();
            int CallingFrameIndex = 2;
            StackFrame frame = callStack.GetFrame(CallingFrameIndex); // Find the frame that called the log function
            while (frame.GetMethod().DeclaringType == typeof(Logger))
            //while (frame.GetMethod().Name == "Debug" || frame.GetMethod().Name == "Info" || frame.GetMethod().Name == "Warn" || frame.GetMethod().Name == "Error")
            {
                CallingFrameIndex++;
                frame = callStack.GetFrame(CallingFrameIndex);
            }
            MethodBase method = frame.GetMethod();
            return method.DeclaringType.Name + "::" + method.Name;
        }
    }
}

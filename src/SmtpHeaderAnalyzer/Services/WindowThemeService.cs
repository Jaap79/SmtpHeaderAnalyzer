using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace SmtpHeaderAnalyzer.Services;

internal static class WindowThemeService
{
    private const int DwmwaUseImmersiveDarkModeBefore20H1 = 19;
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;

    public static void Apply(Window window, bool darkMode)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;

        var enabled = darkMode ? 1 : 0;
        if (DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref enabled, Marshal.SizeOf<int>()) != 0)
        {
            DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkModeBefore20H1, ref enabled, Marshal.SizeOf<int>());
        }

        SetColor(handle, DwmwaCaptionColor, darkMode ? ToColorRef(20, 23, 28) : ToColorRef(255, 255, 255));
        SetColor(handle, DwmwaTextColor, darkMode ? ToColorRef(241, 244, 246) : ToColorRef(23, 32, 42));
        SetColor(handle, DwmwaBorderColor, darkMode ? ToColorRef(53, 60, 71) : ToColorRef(201, 208, 216));
    }

    private static void SetColor(IntPtr handle, int attribute, uint value) =>
        DwmSetWindowAttribute(handle, attribute, ref value, Marshal.SizeOf<uint>());

    private static uint ToColorRef(byte red, byte green, byte blue) => (uint)(red | (green << 8) | (blue << 16));

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr windowHandle, int attribute, ref int value, int size);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr windowHandle, int attribute, ref uint value, int size);
}

@echo off
rem Builds LanDrop.exe with the C# compiler that comes with Windows (.NET Framework 4.8).
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /codepage:65001 /target:winexe /optimize+ /out:"%~dp0LanDrop.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Core.dll "%~dp0LanDrop.cs"

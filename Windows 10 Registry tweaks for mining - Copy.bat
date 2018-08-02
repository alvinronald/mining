@ECHO OFF
COLOR 1F
SET V=1.7
TITLE Windows 10 Registry tweaks for mining (x64) by: jsanzsp
ECHO #########################################################
ECHO #                                                       #
ECHO #  WINDOWS 10 BUILD 10240 X64                           #
ECHO #                                                       #
ECHO #                                                       #
ECHO #  AUTOR: jsanzsp Ethereum Community Forum              #
ECHO #                                                       #
ECHO #########################################################

REM ======================= Registry tweaks =======================
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > NUL 2>&1

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

ECHO Done...

REM ======================= Removing services =======================

sc config DiagTrack start= disabled > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1
sc config TrkWks start= disabled > NUL 2>&1
sc config WMPNetworkSvc start= disabled > NUL 2>&1

sc config dmwappushservice start= disabled > NUL 2>&1

sc config WSearch start= disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

sc config SysMain start= disabled > NUL 2>&1

sc config WinDefend start= disabled > NUL 2>&1
sc config WdNisSvc start= disabled > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1

ECHO Done...

REM ======================= Removing scheduled tasks =======================
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1

ECHO Done...

REM ======================= Removing Windows default apps =======================

powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > NUL 2>&1

ECHO Done...

REM ======================= Disable / Remove OneDrive =======================
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1

ECHO Done...

REM ======================= Blocking Telemetry Servers =======================

copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1

ECHO Finish nice mining!!
ECHO Press a key to exit.
PAUSE > NUL
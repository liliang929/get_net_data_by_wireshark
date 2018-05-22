#######################    Run on PowerShell 3.0 +
#######################    Author:              liuhaiyuan
#######################    Create Date:         2018-05-20          V0.1

<#
.Synopsis
   Get installed software list by retrieving registry.
.DESCRIPTION
   The function return a installed software list by retrieving registry from below path;
   1.'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
   2.'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
   3.'HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
   Author: Mosser Lee (http://www.pstips.net/author/mosser/)

.EXAMPLE
   Get-InstalledSoftwares
.EXAMPLE
   Get-InstalledSoftwares  | Group-Object Publisher
#>
function Get-InstalledSoftwares
{
    #
    # Read registry key as product entity.
    #
    function ConvertTo-ProductEntity
    {
        param([Microsoft.Win32.RegistryKey]$RegKey)
        $product = '' | select Name,Publisher,Version
        $product.Name =  $_.GetValue("DisplayName")
        $product.Publisher = $_.GetValue("Publisher")
        $product.Version =  $_.GetValue("DisplayVersion")

        if( -not [string]::IsNullOrEmpty($product.Name)){
            $product
        }
    }

    $UninstallPaths = @(,
    # For local machine.
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    # For current user.
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')

    # For 32bit softwares that were installed on 64bit operating system.
    if([Environment]::Is64BitOperatingSystem) {
        $UninstallPaths += 'HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    $UninstallPaths | foreach {
        Get-ChildItem $_ | foreach {
            ConvertTo-ProductEntity -RegKey $_
        }
    }
}

# 获取wireshark信息
$name = $(Get-InstalledSoftwares  | Where-Object {$_.Name -like "*Wireshark*"})

if ($name.Name -like "*wireshark*"){
    Write-Output "检测到您的电脑上已有wireshark，自动运行10秒收集数据信息，请稍后。"
    $fileName = $name.Name -split " "
    $wireshark = $fileName[0]
    Start-Process $wireshark
    $shark = Get-Process -Name wireshark
    $file = Dir $($shark.Path)
    $file.DirectoryName
    $tshark_path = $file.DirectoryName + "\tshark.exe"
    $tshark_path
    & "$tshark_path" -a duration:10 -w automatic_capture.pcapng
    Stop-Process -Name $wireshark
    $editcap_path = $file.DirectoryName + "\editcap.exe"
    $editcap_path
    #5秒钟切割分段
    & "$editcap_path" -i 5   automatic_capture.pcapng out.pcapng
    #& 'C:\Program Files\Wireshark\tshark.exe' -a duration:10 -w D:\test2.pcapng
}else {
    Write-Error "未在您的电脑上检测到wireshark软件，请安装wireshark软件。"
}

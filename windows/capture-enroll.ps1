<#
.SYNOPSIS
    Capture the Windows ControlVault 3 fingerprint enrollment over USB with USBPcap.

.DESCRIPTION
    This is the decisive experiment from "Open Questions.md": the Windows stack is the only
    available source of a *working* 0x6C exchange. Capture an enrolment here, then diff the
    0x6C transaction against captures/cv-enroll5.pcap to find the 0x8C precondition.

    Both the \.\USBPcapN control device and the USB device address are discovered at run time
    through USBPcap's extcap interface. Neither is stable: the control device numbering shifts
    when a controller's filter attaches or detaches across reboots, and the device address is
    assigned by the host controller, so it is not the PnP port number. Hardcoding either one
    silently captures the wrong hub or the wrong device rather than failing.

    Run from an elevated PowerShell - USBPcap needs Administrator to open its control device,
    and reports "Couldn't open device - 2" if it does not have it.

.EXAMPLE
    .\capture-enroll.ps1 -Seconds 180 -Out ..\captures\win-enroll1.pcap

.EXAMPLE
    .\capture-enroll.ps1 -List
#>
[CmdletBinding()]
param(
    # How long to capture. Start it, enrol the finger, wait for it to stop.
    [int]$Seconds = 180,

    # Output pcap path. Relative paths resolve against this script's directory.
    [string]$Out = "..\captures\win-enroll1.pcap",

    # Substring identifying the target in USBPcap's device listing.
    [string]$Match = "ControlVault",

    # Just show what was discovered and exit without capturing.
    [switch]$List
)

$ErrorActionPreference = 'Stop'

$UsbPcap = "$env:ProgramFiles\USBPcap\USBPcapCMD.exe"
$Tshark  = "$env:ProgramFiles\Wireshark\tshark.exe"

if (-not (Test-Path $UsbPcap)) { throw "USBPcapCMD not found at $UsbPcap" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated - USBPcap needs Administrator to open its control device."
}

# USBPcapCMD loses buffered stdout when PowerShell captures it through a pipe - the identical
# call yields the full listing on one run and nothing on the next. Redirecting to a file is
# deterministic, so every invocation goes through here.
function Invoke-UsbPcapLines {
    param([string[]]$Arguments)

    $tmp = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $UsbPcap -ArgumentList $Arguments `
                           -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp
        if ($p.ExitCode -ne 0) { Write-Verbose "USBPcapCMD $Arguments exited $($p.ExitCode)" }
        Get-Content $tmp
    }
    finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

# --- 1. Find the control device and USB address of the target --------------------------------

# USBPcapCMD's interactive listing cannot be scraped: with stdout on a pipe the CRT buffers it
# fully, and the program blocks forever on the menu prompt without flushing. The extcap
# interface is the non-interactive route to the same information.
$interfaces = Invoke-UsbPcapLines @('--extcap-interfaces') |
    ForEach-Object { if ($_ -match '\{value=([^}]+)\}') { $Matches[1] } }

if (-not $interfaces) { throw "USBPcap reported no capture interfaces. Is the driver installed?" }

$control = $null
$address = $null
$where   = @()

foreach ($iface in $interfaces) {
    $config = Invoke-UsbPcapLines @('--extcap-interface', $iface, '--extcap-config')

    foreach ($line in $config) {
        # Root devices look like   value {arg=99}{value=1}{display=[1] USB Composite Device}
        # Children carry a parent  value {arg=99}{value=1_1}{display=...}{parent=1}
        if ($line -notmatch '\{value=([0-9_]+)\}\{display=([^}]*)\}') { continue }
        $val = $Matches[1]
        $disp = $Matches[2]

        if ($val -notmatch '_') { $where += "  $iface  $disp" }

        if ($disp -like "*$Match*") {
            # Walk up to the top-level device: its value is the host-assigned USB address.
            $control = $iface
            $address = ($val -split '_')[0]
        }
    }
}

Write-Host "USB devices visible to USBPcap:"
$where | ForEach-Object { Write-Host $_ }
Write-Host ""

if (-not $control) {
    throw @"
No device matching '$Match' is behind any USBPcap control device.

If the ControlVault is present in Device Manager but absent above, USBPcap's filter has not
attached to its controller. Reboot and re-run - the USBPcap installer reports "Reboot required"
for any controller it could not restart in place.
"@
}

Write-Host "Target       : $Match"
Write-Host "Control dev  : $control"
Write-Host "USB address  : $address"

if ($List) { return }

# --- 2. Capture --------------------------------------------------------------------------------

$OutFull = if ([IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path $PSScriptRoot $Out }
$OutDir  = Split-Path -Parent $OutFull
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
if (Test-Path $OutFull) { throw "$OutFull already exists - pick another -Out so an earlier capture is not clobbered." }

Write-Host ""
Write-Host "Capturing to $OutFull for ${Seconds}s."
Write-Host ""
Write-Host "  >>> Enrol the finger NOW: Settings > Accounts > Sign-in options > Fingerprint recognition."
Write-Host "  >>> Complete the whole enrolment. The capture stops on its own."
Write-Host ""

# --devices scopes the capture to the ControlVault, leaving the webcam and Bluetooth radio that
# share its hub out of the trace. --inject-descriptors writes the descriptors of the
# already-enumerated device so the trace is decodable without a replug.
$cmdArgs = @(
    '-d', $control,
    '-o', $OutFull,
    '-s', '65535',
    '-b', '134217728',
    '--devices', $address,
    '--inject-descriptors'
)
$proc = Start-Process -FilePath $UsbPcap -ArgumentList $cmdArgs -PassThru -NoNewWindow

for ($i = $Seconds; $i -gt 0; $i--) {
    Write-Host -NoNewline "`r  $i s remaining ...   "
    Start-Sleep -Seconds 1
    if ($proc.HasExited) { break }
}
Write-Host ""

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Start-Sleep -Seconds 1

# --- 3. Report ---------------------------------------------------------------------------------

if (-not (Test-Path $OutFull)) { throw "No capture file was produced." }

$size = (Get-Item $OutFull).Length
Write-Host ""
Write-Host "Wrote $OutFull ($size bytes)"

if (Test-Path $Tshark) {
    $count = (& $Tshark -r $OutFull -T fields -e frame.number 2>$null | Measure-Object).Count
    Write-Host "Packets      : $count"

    # An idle device still yields the six injected descriptor packets, so packet count - not file
    # size - is what distinguishes "nothing happened" from "the filter never attached".
    if ($count -le 8) {
        Write-Warning "Only the injected descriptors were captured - no enrolment traffic. Did the enrolment actually run?"
    }
}

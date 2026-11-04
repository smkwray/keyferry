# Handheld Messages from PowerShell

Open **Messages** on the handheld and plug it into the computer. Windows' built-in driver presents
it as a serial port named "Keyferry Messages" (USB 303A:4014). Any program that can write a line
to that port can put a message on the screen; nothing needs installing.

The port is display-only. It cannot type, click, read files or reach Keyferry, and the board keeps
the last 16 messages in memory until it restarts (ADR 0018 rule 15).

## Lines

Computer to board, one per line (UTF-8; up to 160 characters are shown):

| Line | Shows |
|---|---|
| `text` | a notice |
| `!text` | an alert (red) |
| `?text` | a question with Yes and No buttons |
| `/clear` | removes every message |
| `/ping` | nothing; the board answers `pong` |

Board to computer, while a program has the port open:

| Line | When |
|---|---|
| `ready` | the port was opened |
| `ok <id>` | a message arrived and is on the screen |
| `read <id>` | someone tapped that notice or alert |
| `yes <id>` / `no <id>` | someone answered that question |

A new message wakes the screen.

## PowerShell (Windows PowerShell 5.1 or PowerShell 7)

```powershell
# Puts one message on the Keyferry handheld. A question waits for Yes ($true) or No ($false).
function Send-Keyferry {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('notice', 'alert', 'question')][string]$Kind = 'notice',
        [int]$TimeoutSeconds = 600
    )
    $device = Get-CimInstance Win32_PnPEntity -Filter "PNPClass = 'Ports'" |
        Where-Object { $_.PNPDeviceID -like 'USB\VID_303A&PID_4014*' } | Select-Object -First 1
    if (-not $device -or $device.Name -notmatch '\((COM\d+)\)') {
        throw 'Keyferry Messages is not connected: open Messages on the handheld.'
    }
    $prefix = @{ notice = ''; alert = '!'; question = '?' }[$Kind]
    $port = [System.IO.Ports.SerialPort]::new($Matches[1])
    $port.NewLine = "`n"
    $port.DtrEnable = $true
    $port.ReadTimeout = 2000
    try {
        $port.Open()
        $port.WriteLine($prefix + ($Text -replace '[\r\n]+', ' '))
        do { $line = $port.ReadLine().Trim() } until ($line -like 'ok *')
        if ($Kind -ne 'question') { return }
        $id = $line.Substring(3)
        $port.ReadTimeout = 1000
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            try { $line = $port.ReadLine().Trim() } catch [System.TimeoutException] { continue }
            if ($line -eq "yes $id") { return $true }
            if ($line -eq "no $id") { return $false }
        }
        throw "No answer on the handheld within $TimeoutSeconds s."
    } finally {
        $port.Close()
    }
}

Send-Keyferry 'OCR finished: 60 PDFs'
Send-Keyferry 'Build failed: 3 tests' -Kind alert
if (Send-Keyferry 'Delete the 12 duplicate scans?' -Kind question) { 'approved' }
```

Keep the port open while waiting for an answer: an answer given while no program has the port
open is not sent later.

Without the function, from any shell: `cmd /c "echo OCR finished> COM7"` (use the COM number
Device Manager shows for Keyferry Messages).

## If it does not appear

Device Manager should list "Keyferry Messages" under Ports (COM & LPT). A computer whose policy
blocks USB serial ports may not show it, or may refuse to open it; Messages cannot work there.

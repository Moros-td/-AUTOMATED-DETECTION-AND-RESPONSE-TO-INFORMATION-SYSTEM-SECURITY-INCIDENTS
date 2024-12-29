
data_stream.dataset : windows.sysmon_operational AND event.category: process AND process.parent.executable: /.*WinRAR\.exe/ AND process.command_line : /.*\..* \.(cmd|bat|Ink|exe|pif|com).*/
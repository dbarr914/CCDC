Get-ChildItem -Recurse $env:SYSTEMDRIVE\ -Include $global:extensions |
Where-Object { $_.LastWriteAccess -gt (Get-Date).AddHours(-1) } |
Select-Object Name,CreationTime  |
Out-File -FilePath out.txt

# PowerShell script to find 'SaveDirectory' value from 'prowin*.ini' files within 'C:\prowin*' directories




Select-String -Path "C:\ProWin*\32bit\ProWin*.ini" -Pattern "SaveDirectory"

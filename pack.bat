@chcp 1251
IF EXIST dnsrouting_packed DEL /F dnsrouting_packed
"F:\Загрузки\upx-3.96-win64\upx.exe" -oF:\builds\go\src\dnsrouting\dnsrouting_packed F:\builds\go\src\dnsrouting\dnsrouting --lzma -9 --best
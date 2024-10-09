@chcp 1251
IF EXIST dnsrouting_packed DEL /F dnsrouting_packed
"D:\Загрузки\upx-4.2.4-win64\upx.exe" -odnsrouting_packed dnsrouting --lzma -9 --best
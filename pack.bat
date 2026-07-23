@chcp 1251
IF EXIST dnsrouting_packed DEL /F dnsrouting_packed
"D:\Загрузки\upx-5.1.1-win64\upx.exe" -odnsrouting_packed dnsrouting.mipsle-softfloat --lzma -9 --best
pause
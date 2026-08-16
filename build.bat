@echo off
:: Baut map2pdb.exe (mit PE/JCLDEBUG/madExcept-Readern). Delphi 12.3, Win32.
call "C:\Delphi\12.3\bin\rsvars.bat" >nul
cd /d "%~dp0Source"
dcc32 -B -Q -U"C:\Delphi\12.3\lib\win32\release" -NS"System;System.Win;Winapi" map2pdb.dpr
del /q *.dcu 2>nul
echo Fertig.

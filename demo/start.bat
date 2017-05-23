@echo off
rem set exe_dir=%~dp0php\php.exe
rem set exe_dir=D:\php-5.6.15\php.exe

start http://127.0.0.1:9999/index.php
rem if exist %exe_dir% %exe_dir% -S 127.0.0.1:9999 &
php -S 127.0.0.1:9999 &
pause
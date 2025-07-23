@echo off
echo Fixing Unicode characters in Java files...
echo.

cd /d "c:\Users\Shavidika\Desktop\Information Security\Project\V2"

:: Use PowerShell to replace Unicode characters with ASCII equivalents
powershell -Command "Get-ChildItem -Path 'src\main\java' -Filter '*.java' -Recurse | ForEach-Object { $content = Get-Content $_.FullName -Raw -Encoding UTF8; $content = $content -replace '[✅🔐🗳️🎯🎉❌🏛️👥🔒🎭📊📋]', '[OK]'; $content = $content -replace '[🔒🔐]', '[SECURE]'; $content = $content -replace '[🗳️]', '[VOTE]'; $content = $content -replace '[✅]', '[OK]'; $content = $content -replace '[❌]', '[ERROR]'; $content = $content -replace '[🎉]', '[SUCCESS]'; $content = $content -replace '[📊]', '[INFO]'; $content = $content -replace '[🏛️]', '[AUTHORITY]'; $content = $content -replace '[👥]', '[USERS]'; $content = $content -replace '[🎭]', '[ANON]'; $content = $content -replace '[📋]', '[AUDIT]'; Set-Content -Path $_.FullName -Value $content -Encoding UTF8 }"

echo Fixed Unicode characters in Java files.
echo.
echo Now try running: compile.bat
echo.
pause

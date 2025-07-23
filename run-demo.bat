@echo off
echo.
echo 🗳️ SECURE ELECTRONIC VOTING PROTOCOL DEMONSTRATION
echo ================================================
echo.

cd /d "c:\Users\Shavidika\Desktop\Information Security\Project\V2"

:: Check if compiled
if not exist "out\com\voting\demo\VotingDemo.class" (
    echo Classes not found. Compiling first...
    echo.
    call compile.bat
    if errorlevel 1 (
        echo Compilation failed!
        pause
        exit /b 1
    )
)

echo Starting election demonstration...
echo.

java -cp out com.voting.demo.VotingDemo

echo.
echo Demo completed!
pause

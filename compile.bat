@echo off
echo Compiling Secure Electronic Voting Protocol...
echo.

cd /d "c:\Users\Shavidika\Desktop\Information Security\Project\V2"

echo Creating output directory...
if not exist "out" mkdir out

echo.
echo Compiling Java sources...

:: Compile crypto package
echo   - Compiling crypto package...
javac -encoding UTF-8 -d out -cp "src\main\java" src\main\java\com\voting\crypto\*.java

:: Compile core package  
echo   - Compiling core package...
javac -encoding UTF-8 -d out -cp "src\main\java;out" src\main\java\com\voting\core\*.java

:: Compile security package
echo   - Compiling security package...
javac -encoding UTF-8 -d out -cp "src\main\java;out" src\main\java\com\voting\security\*.java

:: Compile demo package
echo   - Compiling demo package...
javac -encoding UTF-8 -d out -cp "src\main\java;out" src\main\java\com\voting\demo\*.java

echo.
echo Compilation complete!
echo.
echo To run the demo:
echo   java -cp out com.voting.demo.VotingDemo
echo.
echo To test individual components:
echo   java -cp out com.voting.crypto.CryptoUtils
echo   java -cp out com.voting.core.ElectionAuthority
echo   java -cp out com.voting.security.MixNetwork
echo.
pause

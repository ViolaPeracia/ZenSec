@echo off
REM ===============================
REM  ZenSec Batch Processor (Batch)
REM ===============================
REM  Overridable binary:  set ZENSEC_BIN=C:\path\to\zensec.exe && batch_zensec.bat
REM  Known limitation: delayed expansion is on, so a filename containing '!'
REM  is truncated at the '!' when echoed. Quoting is otherwise handled by
REM  quoting every path and using %%~fF throughout.

setlocal enabledelayedexpansion

if not defined ZENSEC_BIN set "ZENSEC_BIN=zensec.exe"

echo ===============================
echo  ZenSec Batch Processor
echo ===============================

REM Check the binary before asking anything: report it with the install hint
REM instead of failing after three prompts.
where "%ZENSEC_BIN%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: '%ZENSEC_BIN%' not found in PATH.
    echo        Build it first:  go build -o zensec.exe .
    echo        Or set it:       set ZENSEC_BIN=C:\full\path\to\zensec.exe
    pause
    exit /b 1
)

set /p folder="Enter the full path to the folder to process: "
if "%folder%"=="" (
    echo ERROR: no folder given.
    pause
    exit /b 1
)
if not exist "%folder%\" (
    echo ERROR: '%folder%' is not a directory.
    pause
    exit /b 1
)

set /p keyfile="Enter the full path to your keyfile: "
if "%keyfile%"=="" (
    echo ERROR: no keyfile given.
    pause
    exit /b 1
)
REM A trailing backslash matches directories only, so this rejects a folder
REM path passed as the keyfile.
if not exist "%keyfile%" (
    echo ERROR: '%keyfile%' does not exist.
    pause
    exit /b 1
)
if exist "%keyfile%\" (
    echo ERROR: '%keyfile%' is a directory, not a keyfile.
    pause
    exit /b 1
)

REM Canonicalize the keyfile once so it can be compared against %%~fF.
for %%K in ("%keyfile%") do set "keyfileFull=%%~fK"

set /p mode="Do you want to Encrypt (E) or Decrypt (D)? [E/D]: "

set "ok=0"
set "fail=0"
set "skipped=0"

REM -yes is required here: the CLI's overwrite prompt reads stdin and would hang
REM forever inside this loop. 'if errorlevel 1' (not %ERRORLEVEL%) is used because
REM it is evaluated at execution time, while %ERRORLEVEL% inside a block would be
REM expanded once when the block is parsed.
if /i "%mode%"=="E" (
    echo.
    echo Starting ENCRYPTION process...
    for /R "%folder%" %%F in (*) do (
        if not "%%~xF"==".enc" (
            if /i "%%~fF"=="%keyfileFull%" (
                echo Skipping keyfile inside the processed folder: "%%~fF"
                set /a skipped+=1
            ) else (
                echo Encrypting: "%%~fF"
                "%ZENSEC_BIN%" -encrypt -file "%%~fF" -keyfile "%keyfileFull%" -yes
                if errorlevel 1 (
                    echo    FAILED to encrypt: "%%~fF"
                    set /a fail+=1
                ) else (
                    set /a ok+=1
                )
            )
        )
    )
) else if /i "%mode%"=="D" (
    echo.
    echo Starting DECRYPTION process...
    for /R "%folder%" %%F in (*.enc) do (
        if /i "%%~fF"=="%keyfileFull%" (
            echo Skipping keyfile inside the processed folder: "%%~fF"
            set /a skipped+=1
        ) else (
            echo Decrypting: "%%~fF"
            "%ZENSEC_BIN%" -decrypt -file "%%~fF" -keyfile "%keyfileFull%" -yes
            if errorlevel 1 (
                echo    FAILED to decrypt: "%%~fF"
                set /a fail+=1
            ) else (
                set /a ok+=1
            )
        )
    )
) else (
    echo.
    echo ERROR: invalid choice '%mode%'. Expected E or D.
    pause
    exit /b 1
)

set /a total=ok+fail

echo.
echo ===============================
echo  Summary
echo ===============================
echo  Processed: !total!
echo  Succeeded: !ok!
echo  Failed:   !fail!
if !skipped! gtr 0 echo  Skipped:  !skipped! (keyfile inside folder)

echo.
if !fail! gtr 0 (
    echo Process complete WITH ERRORS.
) else (
    echo Process complete.
)

REM Non-zero exit when any file failed, so callers can detect partial failure.
if !fail! gtr 0 (
    pause
    exit /b 1
)
pause
exit /b 0
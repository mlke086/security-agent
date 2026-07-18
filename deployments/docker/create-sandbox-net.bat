@echo off
REM create-sandbox-net.bat — Create Docker network for sandbox isolation (Windows)
set NET_NAME=%1
if "%NET_NAME%"=="" set NET_NAME=sandbox-net

docker network inspect %NET_NAME% >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Network '%NET_NAME%' already exists.
) else (
    docker network create --driver bridge --subnet=172.28.0.0/16 --gateway=172.28.0.1 --label "security-agent=sandbox" %NET_NAME%
    echo Created network '%NET_NAME%' (172.28.0.0/16)
)

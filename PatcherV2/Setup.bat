@echo off

set w=[38;2;255;255;255m
set g=[38;2;0;255;0m

set r=[38;2;205;0;0m

echo %r% ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦═╗  ╦  ╦╔═╗
echo %r% ╠═╝╠═╣ ║ ║  ╠═╣║╣ ╠╦╝  ╚╗╔╝╔═╝
echo %r% ╩  ╩ ╩ ╩ ╚═╝╩ ╩╚═╝╩╚═   ╚╝ ╚═╝
echo. 
echo  %w%[%g%+%w%] Installing Python packages for PatcherV2...
echo.

:: Ensure pip is up-to-date
python -m pip install --upgrade pip

:: Install required packages
pip install wxPython
pip install requests
pip install python-whois
pip install matplotlib
pip install psutil
pip install Flask
pip install dnspython
pip install Pillow
pip install python-docx
pip install PyMuPDF
pip install phonenumbers
pip install beautifulsoup4
pip install scapy
pip install selenium
pip install impacket
pip install ping3
pip install faker

echo.
echo %w%[%g%+%w%] All packages installed successfully.
pause

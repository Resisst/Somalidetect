# Somalidetect.py
# Attempts to detect the use of Somalifuscator to obfuscate a batch file.
#
# This tool does not guarantee to detect all files protected by
# Somalifuscator however the majority of files protected before the
# github commit "729db3ed7bcc8885cb6074a31cfd6c0f90cd7d14" should be
# detected and possibly files created using an updated version of
# Somalifuscator.
#
# Use of this tool is governed by the GNU General Public License V3
# which can be found in the LICENSE file or found online at the URL
# https://www.gnu.org/licenses/gpl-3.0.txt
#
# -----------------------------------------------------------------------

import time
import sys

SOMALIFUSCATOR_GITHUB = "https://github.com/KDot227/Somalifuscator"
LAST_COMMIT = "729db3ed7bcc8885cb6074a31cfd6c0f90cd7d14"
    # If the file is protected with a later version, this tool may not be able
    # to detect it.

try:
    fp = sys.argv[1]
except:
    fp = input("[*] Could not find file argument, please manually input it: ")
    

fp = fp.replace("\"", "")

try:
    with open(fp, "rb") as f:
        data = f.read()
except:
    try:
        with open(fp, "r") as f:
            data = f.read().encode()
    except:
        print("[*] Unable to open file: {}".format(fp))
        time.sleep(10)
        sys.exit(-1)

utf16mark = False

if [data[0], data[1]] == [255, 254]:
    print("[*] Detected UTF-16 byte order mark!")
    utf16mark = True

data = data.lower()

sigs = [
    b'\x25kdot:~',
    b'>nul 2>&1 || cls',
    b'\x25commonprogramfiles(x86)',
    b'\x25driverdata:~',
    b'\x25psmodulepath:~'
    b'\x25godfather\x25',
    b'$eicar-standard-antivirus-test-file!',
    b'::made by k.dot'
]


if sigs[0] in data or sigs[1] in data and sigs[2] in data and sigs[3] in data and  \
    sigs[4] in data or sigs[5] in data or utf16mark and sigs[6] in data or sigs[7] \
    in data:

    print("[*] Detected use of Somalifuscator!")
    time.sleep(10)
    sys.exit(0)

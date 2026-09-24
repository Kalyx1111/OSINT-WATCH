Offline install
===============
If this computer has no internet access when OswRun.bat / OswRun.sh is first run, pip
install fails. To install fully offline instead:

1. On a computer that DOES have internet, with the same OS and Python version:
     pip download -r ../OswRequirements.txt -d .
   This downloads every .whl file needed into this folder.
2. Copy this whole "wheels" folder (with the downloaded files) into this project's folder,
   replacing the empty one.
3. Run OswRun.bat / OswRun.sh as usual - it detects the online install failed and installs
   from these files instead with:
     pip install --no-index --find-links wheels -r OswRequirements.txt

This folder is intentionally empty until you populate it this way.

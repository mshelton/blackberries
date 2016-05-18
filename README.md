# README - Threat Central

Maltego transform for Threat Central.

## Installation instructions

1) Install setuptools.

   Open a terminal. 
   ```
   curl https://bootstrap.pypa.io/ez_setup.py -s -o - | sudo python
   ```
2) Unzip ThreatCentral.zip in the terminal cd to the unzipped ThreatCentral folder.
   ```
   sudo python setup.py install
   ```
   Enter your password if needed.
   This setup  installs all the required Python modules.
   

3) Run the config script (without sudo).
   ```
   python configure.py --init
   ```
   This script checks the canari and ThreatCentral configuration and creates the ThreatCentral transform configuration file for Maltego.
   
   If the script completes without errors, you need to create an API key for Threat Central, as follows:
   ```
   python configure.py --apikey
   ```
   You will be prompted for your Threat Central credentials.

4) Import the ThreatCentral transform configuration file in Maltego

   If the process completed successfully, then you receive the following message:

%%%%%%%%%%%%%%%%%%%%%%%%%%% SUCCESS! %%%%%%%%%%%%%%%%%%%%%%%%%%%

 Successfully created ThreatCentral/ThreatCentral.mtz. You may now import this file into
 Maltego.

 INSTRUCTIONS:
 -------------
 1. Open Maltego.
 2. Click on the home button (Maltego icon, top-left corner).  
 3. Click on 'Import'.
 4. Click on 'Import Configuration'.
 5. Follow prompts.
 6. Enjoy!

%%%%%%%%%%%%%%%%%%%%%%%%%%% SUCCESS! %%%%%%%%%%%%%%%%%%%%%%%%%%%

You need to import the configuration file into Maltego. You can do this by following the instructions above.


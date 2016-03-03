# README - Threat Central

Maltego transform for Threat Central.

Install instructions:

Step 1: Install setuptools

Open a terminal 

curl https://bootstrap.pypa.io/ez_setup.py -s -o - | sudo python


Step 2: Unzip ThreatCentral.zip

In the terminal cd to the unzipped ThreatCentral folder.

sudo python setup.py install

Insert your password if needed.

This setup should install all the needed Python modules.


Step 3: Run the config script (without sudo)

python configure.py --init

This will check the canari and ThreatCentral configuration and wil create the ThreatCentral transform configuration file for Maltego

If above completed without any errors, the api key for Threat Central needs to be created :

python configure.py --apikey

You will be prompted for your Threat Central account details.


Step 4 : Import the ThreatCentral transform configuration file in Maltego

If everything went ok , you should have seen this :

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

In Maltego you will need to import the configuration file, you can do this by following the instructions above.


#!/usr/bin/env python
from sys import exit
from os import name, makedirs
from os.path import join, expanduser, isdir, isfile

import argparse


class CreateProfile:
    # Use the default directory
    working_dir = join(expanduser('~'), '.canari')
    package = 'ThreatCentral'

    def __init__(self):
        pass


def run_canari_profile():
    print "Creating configuration file for Maltego."
    try:
        from canari.commands.create_profile import create_profile
    except ImportError:
        print "Failed creating configuration file for Maltego!"
        print "Please run : canari create-profile ThreatCentral"
        exit("IF this fails, please reinstall the Canari framework.")
    else:
        create_profile(CreateProfile())


def insert_account_details():
    print "Loading canari.easygui ..."
    try:
        from canari.easygui import multpasswordbox
    except ImportError:
        print "Failed loading canari.easygui, trying to read from commandline"
        try:
            from getpass import getpass
        except ImportError:
            print "Failed loading getpass module, please add your Threat Central account details to {}".format(
                join(expanduser("~"), '.canari', 'ThreatCentral.conf'))
        else:
            print "Please insert your Threat Central account details"
            print ""
            return raw_input("Username: "), getpass()
    else:
        return multpasswordbox(msg='Please enter your username and password for Threat Central',
                               title='Threat Central', fields=('username', 'password'))


def save_apikey():
    try:
        from ThreatCentral.transforms.common.client import generate_apikey, set_to_config
    except ImportError as e:
        print "Failed loading ThreatCentral module, please reinstall ThreatCentral"
        exit(e)
    else:
        acc_details = insert_account_details()
        if acc_details:
            api_key = generate_apikey(acc_details[0], acc_details[1])
            return set_to_config(option='apikey', value=api_key[0])


def check_config_file():
    try:
        from ThreatCentral.transforms.common.client import (get_from_config, set_to_config, canari_conf_path)
    except ImportError as e:
        print "Failed loading modules {}".format(e)
    else:
        print "Checking default {} ...".format(canari_conf_path)
        if not isfile(join(expanduser("~"), '.canari', 'canari.conf')):
            print "{} not found, creating file...".format(canari_conf_path)
            try:
                open(join(expanduser("~"), '.canari', 'canari.conf'), 'w').write('[default]')
                if not set_to_config(option='configs', value='ThreatCentral.conf', section='default',
                                     path=canari_conf_path):
                    exit("Failed to set the default values in {} !".format(canari_conf_path))
                if not set_to_config(option='path', value='${PATH}', section='default',
                                     path=canari_conf_path):
                    exit("Failed to set the default values in {} !".format(canari_conf_path))
            except IOError:
                exit("Failed creating {}".format(canari_conf_path))
        d = get_from_config(option='configs', section='default', path=canari_conf_path)
        if not d and d != '':
            if not set_to_config(option='configs', value='ThreatCentral.conf', section='default',
                                 path=canari_conf_path):
                exit("Failed to set the default values in {} !".format(canari_conf_path))

        d = get_from_config(option='path', section='default', path=canari_conf_path)
        if not d and d != '':
            if not set_to_config(option='path', value='${PATH}', section='default',
                                 path=canari_conf_path):
                exit("Failed to set the default values in {} !".format(canari_conf_path))

        d = get_from_config(option='packages', section='remote', path=canari_conf_path)
        if not d and d != '':
            print "Default canari file is missing some default values, trying to add these ..."
            if not set_to_config(option='packages', value='', section='remote', path=canari_conf_path):
                exit("Failed to set the default values in {} !".format(canari_conf_path))
            else:
                print "{} OK".format(canari_conf_path)
        else:
            print "{} OK".format(canari_conf_path)


def check_user_rights():
    try:
        from platform import platform
    except ImportError:
        quit('Cannot load platform module')
    else:
        if not platform() and platform() != '' and platform()[:7].lower() != 'windows':
            try:
                from os import geteuid, getlogin, setgid, setuid
            except ImportError:
                quit('Cannot load geteuit, getlogin, setgid or setuid, quitting!')
            else:
                if name == 'posix' and not geteuid():
                    login = getlogin()

                    if login != 'root':
                        print "Bringing down user rights"
                        try:
                            import pwd
                        except ImportError as e:
                            exit("Failed loading the pwd module!")
                        else:
                            user = pwd.getpwnam(login)
                            setgid(user.pw_gid)
                            setuid(user.pw_uid)


def init():
    # Threat Central now accepts API Keys, removing keyring

    print "Checking canari configuration ..."
    try:
        print "Loading Modules..."
        # from ThreatCentral.transforms.common.client import (check_config, get_from_config, set_to_config,
        #                                                     canari_conf_path, set_to_keyring)
        from ThreatCentral.transforms.common.client import (check_config, get_from_config, set_to_config,
                                                            canari_conf_path)
    except ImportError:
        exit("Failed loading some ThreadCentral modules, please reinstall ThreatCentral!")
    except KeyboardInterrupt:
        exit("Quiting")
    else:
        if isdir(join(expanduser("~"), '.canari')):
            print "canari folder OK"
            check_config_file()
            # run_canari_profile()
        else:
            print "{} folder not found, creating...".format(join(expanduser("~"), '.canari'))
            try:
                makedirs(join(expanduser("~"), '.canari'))
            except IOError as e:
                print "Print failed creating {} : {}".format(join(expanduser("~"), '.canari'), e)
            else:
                check_config_file()
                # run_canari_profile()


def interactive():
    q = raw_input("Do you want to initialize the Canari configuration files? y/N ").lower().strip()
    if q == 'y':
        init()

    q = raw_input("Do you want to setup the API key? y/N ").lower().strip()
    if q == 'y':
        if save_apikey():
            print 'API KEY saved to {}'.format(join(expanduser("~"), '.canari', 'ThreatCentral.conf'))
        else:
            print 'Failed saving API KEY to {}'.format(join(expanduser("~"), '.canari', 'ThreatCentral.conf'))

    q = raw_input("Do you want to create the config file for Maltego? y/N ").lower().strip()
    if q == 'y':
        run_canari_profile()

if __name__ == '__main__':
    # Bring down user rights
    check_user_rights()

    parser = argparse.ArgumentParser(description="Configures Maltego Threat Central package")
    parser.add_argument('--init', action="store_true", help="Initializes configuration files")
    parser.add_argument('--apikey', action="store_true", help="Registers apikey and saves to configuration file")
    parser.add_argument('--configure', action="store_true", help="Runs Canari create-profile to create the Maltego "
                                                                 "configuration file")
    parser.add_argument('--interactive', action='store_true', help="Interactive mode")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    args = parser.parse_args()

    if args.init:
        init()

    elif args.apikey:
        if save_apikey():
            print 'API KEY saved to {}'.format(join(expanduser("~"), '.canari', 'ThreatCentral.conf'))
        else:
            print 'Failed saving API KEY to {}'.format(join(expanduser("~"), '.canari', 'ThreatCentral.conf'))
    elif args.configure:
        run_canari_profile()
    else:
        # run interactive modes to makes it easier.
        interactive()

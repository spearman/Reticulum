##########################################################
# This RNS example demonstrates sending and receiving    #
# symmetrically encrypted data over a GROUP destination. #
##########################################################

import os
import sys
import argparse
import RNS
from RNS.Cryptography import Token

# Let's define an app name. We'll use this for all
# destinations we create. Since this basic example
# is part of a range of example utilities, we'll put
# them all within the app namespace "example_utilities"
APP_NAME = "example_utilities"

# A group keys file holds the private key of an identity
# shared by all group members (used only to derive a
# common destination address), followed by the
# symmetric key used to encrypt group traffic.
IDENTITY_LENGTH = RNS.Identity.KEYSIZE//8

# Length of the AES-256 key created by Token.generate_key()
KEY_LENGTH      = 64

# Creates a new group keys file, that can then be copied
# to all members of the group
def create_group(group_path):
    if os.path.isfile(group_path):
        RNS.log("The group keys file "+group_path+" already exists, not overwriting it", RNS.LOG_ERROR)
        sys.exit(1)

    identity = RNS.Identity()
    key      = Token.generate_key()

    # The keys are secret, so we make the file
    # readable by the current user only
    with os.fdopen(os.open(group_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as group_file:
        group_file.write(identity.get_private_key()+key)

    RNS.log("Created new group keys file "+group_path)
    RNS.log("Copy this file to all group members. Anyone holding it can read group traffic!")

# Loads the shared identity and symmetric key from a
# group keys file
def load_group(group_path):
    if not os.path.isfile(group_path):
        RNS.log("Group keys file "+group_path+" not found, create one with --create", RNS.LOG_ERROR)
        sys.exit(1)

    with open(group_path, "rb") as group_file:
        group_keys = group_file.read()

    if len(group_keys) != IDENTITY_LENGTH+KEY_LENGTH:
        RNS.log("Invalid group keys file "+group_path, RNS.LOG_ERROR)
        sys.exit(1)

    identity = RNS.Identity.from_bytes(group_keys[:IDENTITY_LENGTH])
    if identity == None:
        RNS.log("Could not load identity from group keys file "+group_path, RNS.LOG_ERROR)
        sys.exit(1)

    key = group_keys[IDENTITY_LENGTH:]

    return identity, key

# This initialisation is executed when the program is started
def program_setup(configpath, channel, group_path):
    identity, key = load_group(group_path)

    # We must first initialise Reticulum
    reticulum = RNS.Reticulum(configpath)

    # GROUP packets are only exchanged directly between
    # instances sharing an interface. A shared instance
    # will not pass them on to and from its local clients,
    # so this program must be the Reticulum instance itself.
    if reticulum.is_connected_to_shared_instance:
        RNS.log("Connected to a shared Reticulum instance, but GROUP packets are not passed through it.", RNS.LOG_ERROR)
        RNS.log("Stop rnsd, or use a --config with \"share_instance = No\".", RNS.LOG_ERROR)
        sys.exit(1)

    # We create a GROUP destination. All members use the
    # same identity, so they all arrive at the same
    # destination address, and the same symmetric key,
    # so they can all read each other's traffic.
    group_destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.GROUP,
        APP_NAME,
        "group",
        channel
    )

    group_destination.load_private_key(key)

    # We specify a callback that will get called every time
    # the destination receives data.
    group_destination.set_packet_callback(packet_callback)

    # Everything's ready!
    # Let's hand over control to the main loop
    groupLoop(group_destination)

def packet_callback(data, packet):
    # Simply print out the received data
    print("")
    print("Received data: "+data.decode("utf-8")+"\r\n> ", end="")
    sys.stdout.flush()

def groupLoop(destination):
    # Let the user know that everything is ready
    RNS.log(
        "Group example "+
        RNS.prettyhexrep(destination.hash)+
        " running, enter text and hit enter to send to the group (Ctrl-C to quit)"
    )

    # We enter a loop that runs until the users exits.
    # If the user hits enter, we will send the information
    # that the user entered into the prompt.
    while True:
        print("> ", end="")
        entered = input()

        if entered != "":
            data = entered.encode("utf-8")
            if len(data) > RNS.Packet.ENCRYPTED_MDU:
                RNS.log("Message too long, maximum is "+str(RNS.Packet.ENCRYPTED_MDU)+" bytes", RNS.LOG_ERROR)
            else:
                packet = RNS.Packet(destination, data)
                packet.send()



##########################################################
#### Program Startup #####################################
##########################################################

# This part of the program gets run at startup,
# and parses input from the user, and then starts
# the program.
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
            description="Reticulum example demonstrating encrypted group communication"
        )

        parser.add_argument(
            "--config",
            action="store",
            default=None,
            help="path to alternative Reticulum config directory",
            type=str
        )

        parser.add_argument(
            "--channel",
            action="store",
            default="default",
            help="group channel name",
            type=str
        )

        parser.add_argument(
            "--group",
            action="store",
            default="group.keys",
            help="path to group keys file",
            type=str
        )

        parser.add_argument(
            "--create",
            action="store_true",
            default=False,
            help="create a new group keys file and exit"
        )

        args = parser.parse_args()

        if args.create:
            create_group(args.group)
        else:
            program_setup(args.config, args.channel, args.group)

    except KeyboardInterrupt:
        print("")
        sys.exit(0)

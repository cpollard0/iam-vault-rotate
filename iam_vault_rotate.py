#!/usr/bin/python
"""
used to automatically rotate access keys in IAM that are
stored using ansible vault
"""
import argparse
import io
import logging
import sys
import time
import ansible
from ansible.parsing.vault import VaultLib
import boto3
from ruamel import yaml
from ruamel.yaml.scalarstring import LiteralScalarString

ANSIBLE_VER = float('.'.join(ansible.__version__.split('.')[:2]))

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

def ansible_vault_ctor(self, node):
    """yaml constructor to handle !vault function. Not doing anything, just passing it back"""
    # pylint: disable=unused-argument
    return node.value

def make_secret(secret):
    """ creates vault secret based on the version of ansible being ran"""
    if ANSIBLE_VER < 2.4:
        return secret

    from ansible.constants import DEFAULT_VAULT_ID_MATCH
    from ansible.parsing.vault import VaultSecret
    return [(DEFAULT_VAULT_ID_MATCH, VaultSecret(secret))]

def get_parser():
    """get the parsers dict"""
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(
        description="Automatically rotate a vault encrypted IAM key")

    subparsers = parsers['super'].add_subparsers(help='Try commands like '
                                                 '"{name} get -h" or "{name} '
                                                 'put --help" to get each '
                                                 'sub command\'s options'
                                                 .format(name=sys.argv[0]))
    action = 'rotate'
    parsers[action] = subparsers.add_parser(action, help="Rotates a credential")
    parsers[action].add_argument("rotationtype", type=str, default="generate",
                                 help="indicates whether you need to generate a new key"
                                 " you are passing in an access key/secret key to rotate to"
                                 " defaults to generate")
    parsers[action].add_argument("encryptiontype", type=str, default="file",
                                 help="indicates whether you encryption is inline or file"
                                 " defaults to file")
    parsers[action].add_argument("-u", "--user", type=str,
                                 help="the name of the user for whom to rotate. "
                                 " If blank will be current user")
    parsers[action].add_argument("-vf", "--vaultfile", default="",
                                 help="location of vault encrypted file")
    parsers[action].add_argument("-af", "--accessfile", default="",
                                 help="location of access key file")
    parsers[action].add_argument("-vp", "--vaultpass",
                                 help="vault password")
    parsers[action].add_argument("-vpf", "--vaultpassfile",
                                 help="vault password file")

    parsers[action].add_argument("-sk", "--secretkeyname", default="vault_aws_secret_key",
                                 help="secret key name")
    parsers[action].add_argument("-ak", "--accesskeyname", default="aws_access_key",
                                 help="access key name. defaults to aws_access_key")

    parsers[action].add_argument("-acck", "--accesskeyvalue", default="",
                                 help="access key to rotate to. used when "
                                 " we don't want to generate a key but rotate it"
                                 " defaults to blank.")

    parsers[action].add_argument("-vid", "--vaultid", default="",
                                 help="Vault Id for use with solutions with multiple vault files")

    parsers[action].add_argument("-d", "--delete_old_access_key", default="FALSE",
                                 help="Delete old access key")
    parsers[action].add_argument("-v", "--verbose", action="store_true",
                                 help="verbose mode")
    parsers[action].set_defaults(action=action)
    return parsers

def generate_new_key(access_key, secret_key, user_to_rotate):
    """generates a new key pair and returns the access key and secret key"""
    LOGGER.info("Begin generate new key")
    iam_client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    resp = iam_client.create_access_key(UserName=user_to_rotate)
    LOGGER.debug(resp)
    LOGGER.info("End generate new key")
    return resp['AccessKey']['AccessKeyId'].strip(), resp['AccessKey']['SecretAccessKey'].strip()

def get_vault_encrypted_file(vault, vault_file_location):
    """gets a vault encrypted file and loads it into yaml"""
    LOGGER.info("Begin get vault encrypted file")
    vault_file = vault.decrypt(open(vault_file_location).read())
    vault_file = yaml.safe_load(vault_file)
    LOGGER.info("End get vault encrypted file")
    return vault_file

def get_current_creds(vault, vault_file_location, access_key_location,
                      access_key_key, secret_key_key, encryption_type):
    """gets the current credentials from group vars"""
    # pylint: disable=too-many-arguments
    LOGGER.info("Begin get current creds")
    if encryption_type == 'file':
        vault_file = get_vault_encrypted_file(vault, vault_file_location)
        current_secret_key = vault_file[secret_key_key]
        current_access_key = yaml.safe_load(open(access_key_location).read())
        c_access_key = current_access_key[access_key_key]
    else:
        vault_file = yaml.safe_load(open(vault_file_location).read())
        current_secret_key = vault.decrypt(vault_file[secret_key_key])
        if vault_file_location == access_key_location:
            c_access_key = vault_file[access_key_key]
        else:
            current_access_key = yaml.safe_load(open(access_key_location).read())
            c_access_key = current_access_key[access_key_key]
    LOGGER.info("End get current creds")
    return c_access_key.strip(), current_secret_key.strip()

def delete_old_key_access_key(access_key, secret_key, key_to_delete, user_to_rotate):
    """deletes the old access keys"""
    LOGGER.info("begin delete old access key")
    iam_delete_client = boto3.client(
        'iam', aws_access_key_id=access_key,
        aws_secret_access_key=secret_key)
    resp = iam_delete_client.delete_access_key(
        AccessKeyId=key_to_delete,
        UserName=user_to_rotate)
    LOGGER.debug(resp)
    LOGGER.info("End delete old access key")
    return resp

def format_vault_encrypted_secret(vault_encrypted_secret):
    """ returns a prettier vault secret """
    # Clean up spacing on the ansible vault line
    vault_encrypted_secret = vault_encrypted_secret.replace("        $ANSIBLE_VAULT", "  $ANSIBLE_VAULT")
    return vault_encrypted_secret

def rotate_cred(vault, args, new_access_key, new_secret_key):
    """rotates an IAM credential"""
    # pylint: disable=too-many-arguments
    # rotate secret
    LOGGER.info("Begin rotate creds")
    if args.encryptiontype == 'file':
        vault_file = get_vault_encrypted_file(vault, args.vaultfile)
        vault_file[args.secretkeyname] = new_secret_key
        with open(args.vaultfile, "w") as outfile:
            outfile.write(vault.encrypt(vault_file))

    else:
        vault_file = yaml.safe_load(open(args.vaultfile).read())
        vault_id = None
        if args.vaultid:
            vault_id = args.vaultid
        new_secret_vaulted = vault.encrypt(new_secret_key.strip(), None, vault_id)
        new_secret_key_local = new_secret_vaulted
        vault_file[args.secretkeyname] = LiteralScalarString(format_vault_encrypted_secret(new_secret_key_local))
        if args.accessfile == args.vaultfile:
            vault_file[args.accesskeyname] = new_access_key
            file_to_write = yaml.round_trip_dump(vault_file)

            # TODO: This is still hacky; but less so? Has to be a more elegant way....
            file_to_write = "---\n" + file_to_write
            file_to_write = file_to_write.replace(args.secretkeyname + ":", args.secretkeyname + ": !vault")
        with io.open(args.vaultfile, "w", encoding="utf-8") as outfile:
            outfile.write(file_to_write.decode('utf-8'))

    # if the access key is in a different location, we need to update that too
    if args.accessfile != args.vaultfile:
        try:
            current_access_key = yaml.safe_load(open(args.accessfile).read())
        # pylint: disable=broad-except
        except Exception as error:
            LOGGER.error("An error occured opening current access key file: %s", error.message)
            return None
        current_access_key[args.accesskeyname] = new_access_key
        file_to_write = yaml.round_trip_dump(current_access_key)
        file_to_write = "---\n" + file_to_write
        with open(args.accessfile, "w") as outfile:
            outfile.write(file_to_write.decode('utf-8'))
    LOGGER.info("End rotate creds")
    return "Rotated"

def get_vault_password(vaultpass, vaultpassfile):
    """ gets vault password file and reutrns it cleaned"""
    LOGGER.info("Begin get vault password")
    try:
        if not vaultpass is None:
            vault_pass = vaultpass
        else:
            vault_pass = open(vaultpassfile).read()
    # pylint: disable=broad-except
    except Exception:
        LOGGER.error("Vault password not set")
    LOGGER.info("End get vault password")
    return vault_pass.rstrip()


def main():
    """main handler"""
    LOGGER.info("Begin rotation")
    parsers = get_parser()
    # add custom constructor for ansible vault encryption
    yaml.SafeLoader.add_constructor('!vault', ansible_vault_ctor)
    args = parsers['super'].parse_args()
    if args.verbose:
        LOGGER.setLevel(logging.DEBUG)
    vault_pass = ""
    vault_pass = get_vault_password(args.vaultpass, args.vaultpassfile)
    LOGGER.debug("Vault Password: %s", vault_pass)
    vault = VaultLib(make_secret(vault_pass))

    current_access_key, current_secret_key = get_current_creds(
        vault,
        args.vaultfile,
        args.accessfile,
        args.accesskeyname,
        args.secretkeyname,
        args.encryptiontype)
    if not args.user is None:
        user_to_rotate = args.user
    else:
        user_to_rotate = boto3.client(
            'sts',
            aws_access_key_id=current_access_key,
            aws_secret_access_key=current_secret_key
            ).get_caller_identity()["Arn"].split('/')[-1]
    try:
        new_access_key, new_secret_key = generate_new_key(
            current_access_key,
            current_secret_key,
            user_to_rotate
        )
        rotate_cred(
            vault,
            args,
            new_access_key,
            new_secret_key
        )
        if args.delete_old_access_key == 'TRUE':
            # set a wait while the created keys get propogated
            LOGGER.info("Begin wait for keys to get propogated")
            time.sleep(30)
            LOGGER.info("End wait for keys to get propogated")
            delete_old_key_access_key(
                new_access_key,
                new_secret_key,
                current_access_key,
                user_to_rotate)
    # pylint: disable=broad-except
    except Exception as error:
        LOGGER.error(error.message)
    LOGGER.info("End rotation")

if __name__ == '__main__':
    main()

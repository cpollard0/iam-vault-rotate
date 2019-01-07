# IAM Vault Rotate

## What is this?

In our automation, we have IAM service accounts that are associated with Ansible solutions.  We store the credentials for these
accounts in the ansible solution using Ansible vault to encrypt secrets. These service accounts are
highly privileged and need to conform to our password rotation policy. There is a service account per AWS environment, meaning
an individual application can have up to 5 service accounts. The overhead burden on rotating these credentials has historically
led to service accounts having an exception from the password expiration policy. As we move to AWS, we want to get away from that.

This utility is a simple utility that rotates a users credentials within an ansible solution.

## Setup

Run:
```
python setup.py install
```

## Usage

Example:

```
iam_vault_rotate rotate generate inline -vpf /vagrant/vault_password_file -vf /vagrant/group_vars/dev1/access_aws.yml -af /vagrant/group_vars/dev1/access_aws.yml -sk aws_secret_key  -d TRUE
```


```
usage: iam_vault_rotate rotate [-h] [-u USER] [-vf VAULTFILE] [-af ACCESSFILE]
                               [-vp VAULTPASS] [-vpf VAULTPASSFILE]
                               [-sk SECRETKEYNAME] [-ak ACCESSKEYNAME]
                               [-acck ACCESSKEYVALUE]
                               [-d DELETE_OLD_ACCESS_KEY]
                               rotationtype encryptiontype

positional arguments:
  rotationtype          indicates whether you need to generate a new key you
                        are passing in an access key/secret key to rotate to
                        defaults to generate
  encryptiontype        indicates whether you encryption is inline or file
                        defaults to file

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  the name of the user for whom to rotate. If blank will
                        be current user
  -vf VAULTFILE, --vaultfile VAULTFILE
                        location of vault encrypted file
  -af ACCESSFILE, --accessfile ACCESSFILE
                        location of access key file
  -vp VAULTPASS, --vaultpass VAULTPASS
                        vault password
  -vpf VAULTPASSFILE, --vaultpassfile VAULTPASSFILE
                        vault password file
  -sk SECRETKEYNAME, --secretkeyname SECRETKEYNAME
                        secret key name in the vault file. defaults to
                        vault_aws_secret_key
  -ak ACCESSKEYNAME, --accesskeyname ACCESSKEYNAME
                        access key name. defaults to aws_access_key
  -acck ACCESSKEYVALUE, --accesskeyvalue ACCESSKEYVALUE
                        access key to rotate to. used when we don't want to
                        generate a key but rotate it defaults to blank.
  -vid VAULTID, --vaultid VAULTID
                        Vault Id for use with solutions with multiple vault files
  -d DELETE_OLD_ACCESS_KEY, --delete_old_access_key DELETE_OLD_ACCESS_KEY
                        Delete old access key

```
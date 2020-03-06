# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys of other users in their organization (or in adjacent
organizations).

## Quick intro

When using OpenPGP CA's centralized key creation workflow, generating
new, mutually authenticated OpenPGP keys for users in your organization is
as simple as running the following commands:

```
export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite
openpgp-ca ca init example.org 

openpgp-ca user add --email alice@example.org --name "Alice Adams"
openpgp-ca user add --email bob@example.org --name "Bob Baker"
```

First we configure an environment variable for the SQLite database in which
all of OpenPGP CA's state will be stored (all persisted data of OpenPGP CA
lives in this single file).

The `ca init` call then creates a new OpenPGP Key for the CA Admin (the
private Key is stored in OpenPGP CA and will be used to sign user keys).

After that, we call `user add` to create new OpenPGP Keys for each of our
users.
The private key material for those users is *not* stored in OpenPGP CA - it
is only printed to stdout (the admin needs to take appropriate steps to get
those keys to the users' machines).

These users can automatically authenticate each other as soon as the
their OpenPGP implementations have copies of the user keys and the OpenPGP
CA admin's key.

For more details and more workflows - including decentralized key
creation, if you prefer to create user keys on the user's machine - see the
documentation below.


## Documentation

https://openpgp-ca.gitlab.io/openpgp-ca/

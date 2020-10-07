# Experimental REST API for OpenPGP CA

To use the OpenPGP CA as a REST service, the CA first needs to be initialized
once (to create the CA key):

```
$ openpgp-ca -d example.oca ca init example.org
```

Then the REST daemon can be started:

```
$ openpgp-ca-restd -d example.oca run

🔧 Configured for development.
    => address: localhost
    => port: 8000
    => log: normal
    => workers: 8
    => secret key: generated
    => limits: forms = 32KiB
    => keep-alive: 5s
    => tls: disabled
🛰  Mounting /:
    => GET /certs/list/<email> (list_certs)
    => GET /certs/check application/json (check_cert)
    => POST /certs application/json (post_user)
    => POST /certs/deactivate/<fp> (deactivate_cert)
    => DELETE /certs/<fp> (delist_cert)
    => POST /refresh_ca_certifications (refresh_certifications)
    => POST /poll_updates (poll_for_updates)
🚀 Rocket has launched from http://localhost:8000
```

## Previewing an OpenPGP certificate (key) addition or update

When a user uploads an OpenPGP certificate (key), our suggested workflow is to
give the user feedback on aspects of that key before asking them if
they want to persist the new data to OpenPGP CA.

There are two reasons for this:

- OpenPGP certificates are typically not in a human-readable form, so it's
  useful to confirm that the user has actually uploaded the right key
- This REST-service potentially normalizes certificates.
  Some data may be removed (such as some user_ids).
  Also, in the case of an update to an existing certificate, information from
  both variants of the certificate will be merged.
  In all of these cases it is good to show the user the resulting data for
  review.

```
curl --header "Content-Type: application/json" --request GET --data @user.json  http://localhost:8000/certs/check
```

The data-file `user.json` contains data in the form:

```
{"email": ["alice@example.org"],
 "name": "Alice Adams",
 "revocations": [],
 "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBF9orW8BEAC9RievEe67QyvqV7XGnGVV2VwMGuoJFtER8xwU0RCSqKMnu6L+
un0wri829zQm/trLebHDD70Dvwe6Wl5gwXJtbKTETMg3KuJ51DAZvo4W0JUkEvwC
[..]
iIJw33bSlyssaXTnnfGR5KySs91HCl8PlZHJBz4D6+Tae27cA14rcrgRewO8YyBZ
=vus6
-----END PGP PUBLIC KEY BLOCK-----"}
```

The output of this call is JSON-formatted information about the certificate
(or an error, if the certificate is not acceptable to our system).

This JSON data should be shown to the user, asking them if they want to
persist the certificate as shown. If they confirm, proceed to the next step to
persist the certificate.

## Persisting OpenPGP certificates

After checking and previewing a certificate addition or update, you can 
persist the data to the OpenPGP CA database via a POST request:

```
curl --header "Content-Type: application/json" --request POST --data @user.json  http://localhost:8000/users/new
```

The format and content of the output of this call is exactly the same as above
for `/certs/check`.

## Revoking a certificate

When a user wants to stop using a certificate, normal procedure is to apply a
"revocation". The revocation marks the certificate as invalid (and can
contain additional information about the reason for revocation).

For the purpose of this API, this operation is just a regular "update" to
the certificate. It has in some sense the semantics of a "delete" operation:
The user's certificate was usable before the revocation - after the
operation it is marked as non-usable.

However, it is necessary to leave this (now invalidated) key accessible on
WKD (ideally indefinitely): This is how third parties will learn of the key's
revocation.


## Listing all OpenPGP certificates for a user

A `user` is identified by their email, in this service.
To get a list of all OpenPGP certificates for a user, call:

```
curl --request GET http://localhost:8000/certs/list/alice@example.org
```

Among other things, the returned data contains fingerprint strings for each
certificate, which are used as keys for the following operations.


## Marking a certificate as deactivated

When a user leaves the organization (such as FSFE), this has subtle
implications for their OpenPGP certificate:

First of all, it probably doesn't mean that the key should be revoked.
A certificate can be associated with various email addresses (this would be
represented by a number of user_ids).
The user may keep using the same key in other contexts, with
other email addresses.

When a user leaves FSFE, it makes sense that FSFE stops to certify the
user_id at FSFE (after all, this email address does not exist anymore).

This is what we mean by "deactivation":
While a user is an FSFE member, the FSFE OpenPGP CA will certify their
user_id `alice@fsfe.org`. After the user has left FSFE, this certification
will not be renewed. FSFE stops to certify that the OpenPGP certificate is
associate with the email address `alice@fsfe.org`

This "deactivate" operation can be performed like this:

```
curl --request POST http://localhost:8000/certs/deactivate/<fingerprint>
```

## Delisting a certificate

It is possible that a certificate should actually not be listed on WKD any
more - however, this is probably very rare. When that operation is
appropriate, it can be performed like this:
 
```
curl --request DELETE http://localhost:8000/certs/<fingerprint>
```

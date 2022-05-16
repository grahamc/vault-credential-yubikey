# Use a yubikey's PIV to log in to Vault

I've made the first 80% of a Vault auth backend to log in with a yubikey.
It fully works, though the docs and enrollment process aren't tops.
About 80% of the work remains.

Note that I no longer have a use case for this auth method.
If you're interested in adopting this project, I'd be happy to help you do so.

Logging in is a two-phase process:

1. The user logging in submits an attestation certificate and statement to the server.
1. The server returns a challenge, and stores that challenge for the yubikey.
1. The yubikey submits the challenge, signed with the attestation statement slot's public key.
1. The server deletes the challenge from the database and logs the user in.

Things that work:

* Registering a yubikey by serial number works.
* After first login, the yubikey's slot public key is fixated.
* Minimum conditions can be required by the attestation:
    * Minimum firmware versions
    * Specifying which slots are valid for logging in.
    * The PIN policy used for that slot
    * The formfactor of the device (for example, FIPS only)

The missing 80%:

* There are very few tests.
* There are no docs beyond this readme.
* The enrollment process is rough.
* For Vault Agent to support it, we'd need to patch the agent to teach it how to use the auth method in ./authmethod.
* Old and abandoned challenges should be periodically pruned.

See ./cmd/attest for an example of how to log in using the authmethod in ./authmethod.

---

Terminal A:

```
make
```

Terminal B:

```
export VAULT_ADDR=http://127.0.0.1:8200
make enable
vault write -force auth/yubikey-auth/yubikey/13993598
vault read auth/yubikey-auth/yubikey/13993598
```

Terminal C:

```
VAULT_ADDR=http://127.0.0.1:8200 ./attest
```

In one terminal run `make`, which will start the Vault server. In another terminal:

```
[nix-shell:~/projects/github.com/grahamc/yubtest]$ export VAULT_ADDR=http://127.0.0.1:8200

[nix-shell:~/projects/github.com/grahamc/yubtest]$ make enable
vault auth enable -path=yubikey-auth vault-plugin-auth-yubikey
Success! Enabled vault-plugin-auth-yubikey auth method at: yubikey-auth/

[nix-shell:~/projects/github.com/grahamc/yubtest]$ vault write -force auth/yubikey-auth/token/13993598 
Success! Data written to: auth/yubikey-auth/token/13993598

[nix-shell:~/projects/github.com/grahamc/yubtest]$ cat payload | curl --data @- http://127.0.0.1:8200/v1/auth/yubikey-auth/login
{"request_id":"05cdf0da-fe8b-e0b9-eb8b-30bc3bb4fbe7","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"hvs.CAESIDRJIk5vMEFsPrcXpP2fNDKlIn1kHfiSdSxcYLusVIvbGh4KHGh2cy5QMEdCMlZMUk02REpGZmFTdXk1ZXpXNEE","accessor":"3Ox4H0ZdSqepChVKjdOFVkmP","policies":["default"],"token_policies":["default"],"metadata":{"serial":"13993598"},"lease_duration":2764800,"renewable":false,"entity_id":"","token_type":"service","orphan":true,"mfa_requirement":null,"num_uses":0}}

```
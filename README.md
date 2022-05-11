
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

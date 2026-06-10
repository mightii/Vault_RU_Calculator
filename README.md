**#vault_pricing.py**

Python script that connects to a HashiCorp Vault cluster, automatically walks through all mounts, and prints a summary of the metrics needed for pricing to the terminal.

## Métrics collected

| Category | Detail |
|---|---|
| **Static secrets (KV)** | Number of unique secrets in KV v1 and v2 mounts |
| **Dynamic secrets** | Number of configured roles (AppRole, Kubernetes, LDAP, AWS, Database...) |
| **PKI** | RU = number of active certificates × (remaining TTL in hours ÷ 730) |
| **SSH** | RU = Σ (TTL of the role in hours ÷ 730) |
| **Transit / Transform / KMSE** | Number of configured keys |

## Prerequisite

```bash
pip3 install requests cryptography
```

> `cryptography` est optionnel mais recommandé — il permet le calcul précis des RU PKI.

## Utilisation

```bash
export VAULT_ADDR=https://<adresse-de-votre-vault>
export VAULT_TOKEN=<votre-token>
export VAULT_NAMESPACE=<namespace>   # optional, only Enterprise/HCP 

python3 vault_pricing.py
```

## Permissions needed

The Vault token used need to have the following rights :

```hcl
path "sys/mounts"   { capabilities = ["read"] }
path "sys/auth"     { capabilities = ["read"] }
path "+/metadata/*" { capabilities = ["list"] }
path "auth/+/role"  { capabilities = ["list"] }
path "+/roles"      { capabilities = ["list"] }
path "pki*/certs"   { capabilities = ["list"] }
path "pki*/cert/*"  { capabilities = ["read"] }
path "+/keys"       { capabilities = ["list"] }
```

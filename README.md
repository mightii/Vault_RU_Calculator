# vault_pricing.py

Script Python qui se connecte à un cluster HashiCorp Vault, parcourt automatiquement tous les mounts et remonte dans le terminal un résumé des métriques nécessaires au pricing.

## Métriques collectées

| Catégorie | Détail |
|---|---|
| **Secrets statiques (KV)** | Nombre de secrets uniques dans les mounts KV v1 et v2 |
| **Secrets dynamiques** | Nombre de rôles configurés (AppRole, Kubernetes, LDAP, AWS, Database...) |
| **PKI** | RU = nombre de certificats actifs × (TTL restant en heures ÷ 730) |
| **SSH** | RU = Σ (TTL du rôle en heures ÷ 730) |
| **Transit / Transform / KMSE** | Nombre de clés configurées |

## Prérequis

```bash
pip3 install requests cryptography
```

> `cryptography` est optionnel mais recommandé — il permet le calcul précis des RU PKI.

## Utilisation

```bash
export VAULT_ADDR=https://<adresse-de-votre-vault>
export VAULT_TOKEN=<votre-token>
export VAULT_NAMESPACE=<namespace>   # optionnel, Enterprise/HCP uniquement

python3 vault_pricing.py
```

## Permissions requises

Le token Vault utilisé doit avoir les droits suivants :

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

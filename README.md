# letsencrypt-caa-bug-checker

This tool will check all cert-manager Certificate resources installed in your
cluster to ensure they are not affected by the
[Let's Encrypt CAA Rechecking Bug](https://community.letsencrypt.org/t/revoking-certain-certificates-on-march-4/114864).

It will:

1) Query your Kubernetes cluster for all Certificate resources
2) Find all Secret resources managed by Certificate resources
3) Check the serial number of each certificate against the publicly available
   list of serial numbers that will be revoked
4) Trigger cert-manager to renew any certificates that are affected by the bug

## Pre-requisites

This tool only works with **cert-manager v0.11 onwards**, as it depends on the
v1alpha2 API. If you are running an older version of cert-manager, please
upgrade by following the [upgrade guide](https://cert-manager.io/docs/installation/upgrading/).

Your Kubernetes user account will need the following permissions:

* Certificate resources (`cert-manager.io/v1alpha2`): LIST
* CertificateRequest resources (`cert-manager.io/v1alpha2`): LIST, DELETE
* Secret resources (`core/v1`): LIST, UPDATE

### Fetching the list of revoked serials

This tool requires a copy of the full list of serial numbers that Let's Encrypt
have notified for revocation.

Use the snippet below to download and extract the file. Decompressed, the file
is approximately 1.2GB, so please ensure you have sufficient free space for
extraction.

```shell
wget -c https://d4twhgtvn0ff5.cloudfront.net/caa-rechecking-incident-affected-serials.txt.gz
zcat < caa-rechecking-incident-affected-serials.txt.gz > serials.txt
```

This snippet is based on the script in the [prepare-lecaa](https://github.com/hannob/lecaa/blob/master/prepare-lecaa)
file in the [hannob/lecaa](https://github.com/hannob/lecaa) repository, with
minor modifications.

## Checking for affected certificates

First, download or build a copy of the `letsencrypt-caa-bug-checker` tool from
this GitHub repository.

First, perform a check of all the Certificates in your cluster to see if any
are affected:

```shell
./letsencrypt-caa-bug-checker --affected-serials-file serials.txt
```

You should see the tool check all resources in your cluster, and after a few
seconds it should print something like:

```shell
...
2020/03/04 16:13:06 +++ Checking Secret resource for Certificate example/demo-prod
2020/03/04 16:13:13 Finished analyzing certificates, results:
2020/03/04 16:13:13   Skipped/unable to check: 0
2020/03/04 16:13:13   Unaffected certificates: 16
2020/03/04 16:13:13   Affected certificates: 3
```

By default, the tool will NOT automatically trigger renewals, and will ONLY
print out analysis information.

## Triggering a renewal

To actually trigger a renewal of these affected certificates, you must add the
`--renew` flag to your command invocation:

```shell
./letsencrypt-caa-bug-checker --affected-serials-file serials.txt --renew
```

A number of warnings will be printed, giving you the opportunity to cancel in
case you have accidentally invoked the command incorrectly.

The tool will now go through and manually trigger a renewal for each affected
Certificate resource.

It does this by changing the `cert-manager.io/issuer-name` annotation on the
Secret resource for each certificate, causing cert-manager to re-request a
new certificate.

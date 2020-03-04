package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/api"
	capi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	affectedSerialsFile string
	renew               bool
)

func init() {
	flag.StringVar(&affectedSerialsFile, "affected-serials-file", "", "The path to the extracted 'affected serials' file.")
	flag.BoolVar(&renew, "renew", false, "If true, any affected certificates will be renewed. This may take a few minutes per Certificate.")
}

func main() {
	flag.Parse()
	if affectedSerialsFile == "" {
		log.Fatal("--affected-serials-file must be specified! Please download and extract the file by running the 'prepare-lecaa' script here: https://github.com/hannob/lecaa")
	}
	if renew {
		log.Printf("!!!!! --renew has been set to TRUE. Any affected certificates will have a renewal automatically triggered if found !!!!!")
		log.Printf("!!!!! Waiting 5s before proceeding, if you DO NOT renewals to be triggered, hit ctrl+c NOW !!!!!")
		time.Sleep(time.Second * 5)
	}
	log.Println("This tool will query a Kubernetes cluster, check if any " +
		"certificates are affected by the Let's Encrypt CAA rechecking bug " +
		"and trigger a renewal of any affected certificates. " +
		"It is safe to run multiple times, and will take no action if " +
		"certificates do not need to be re-issued.")

	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// Build an API client
	cfg := ctrl.GetConfigOrDie()
	mapper, err := apiutil.NewDynamicRESTMapper(cfg)
	if err != nil {
		return err
	}
	cl, err := client.New(cfg, client.Options{
		Scheme: api.Scheme,
		Mapper: mapper,
	})
	if err != nil {
		return fmt.Errorf("error building API client: %w", err)
	}

	var certs capi.CertificateList
	if err := cl.List(ctx, &certs); err != nil {
		return fmt.Errorf("error listing Certificate resources: %w", err)
	}
	log.Printf("Found %d Certificate resources to check", len(certs.Items))
	var secrets core.SecretList
	if err := cl.List(ctx, &secrets); err != nil {
		return fmt.Errorf("error listing Secret resources: %w", err)
	}
	secretsMap := makeSecretsMap(secrets.Items)

	serialsToCertificates := make(map[string]capi.Certificate)
	skipped := 0
	for _, crt := range certs.Items {
		log.Printf("+++ Checking Secret resource for Certificate %s/%s", crt.Namespace, crt.Name)
		secret, ok := secretsMap[crt.Namespace+"/"+crt.Spec.SecretName]
		if !ok {
			log.Printf("Unable to find Secret resource %q, skipping...", crt.Spec.SecretName)
			skipped++
			continue
		}
		if secret.Data == nil || secret.Data[core.TLSCertKey] == nil {
			log.Printf("Secret %q does not contain any data for key %q, skipping...", crt.Spec.SecretName, core.TLSCertKey)
			skipped++
			continue
		}
		certPEM := secret.Data[core.TLSCertKey]
		cert, err := pki.DecodeX509CertificateBytes(certPEM)
		if err != nil {
			log.Printf("Failed to decode x509 certificate data in Secret %q: %v, skipping...", crt.Spec.SecretName, err)
			skipped++
			continue
		}
		serialsToCertificates[fmt.Sprintf("%x", cert.SerialNumber)] = crt
	}
	affected, err := affectedCertificates(serialsToCertificates)
	if err != nil {
		log.Printf("Failed to check if certificates are affected: %v", err)
		return err
	}
	log.Println("Finished analyzing certificates, results:")
	log.Printf("  Skipped/unable to check: %d", skipped)
	log.Printf("  Unaffected certificates: %d", len(serialsToCertificates)-len(affected))
	log.Printf("  Affected certificates: %d", len(affected))
	if len(affected) == 0 {
		return nil
	}
	if !renew {
		log.Println()
		log.Printf("Will NOT trigger a renewal as --renew set to false")
		return nil
	}

	log.Println()
	log.Printf("Will now attempting to renew the following certificates:")
	for sn, cert := range affected {
		log.Printf("  * %s/%s (serial number: %s)", cert.Namespace, cert.Name, sn)
	}
	log.Println()
	log.Printf("!!!!! Will now attempt to renew %d certificates, waiting 2s... !!!!!", len(affected))
	time.Sleep(time.Second * 2)
	log.Println()

	for _, cert := range affected {
		log.Printf("Triggering renewal of Certificate %s/%s", cert.Namespace, cert.Name)
		if err := renewCertificate(ctx, cl, cert); err != nil {
			log.Printf("Failed to renew certificate %s/%s: %v", cert.Namespace, cert.Name, err)
			return err
		}
	}
	return nil
}

func renewCertificate(ctx context.Context, cl client.Client, cert capi.Certificate) error {
	var requests capi.CertificateRequestList
	if err := cl.List(ctx, &requests, client.InNamespace(cert.Namespace)); err != nil {
		return err
	}
	for _, req := range requests.Items {
		// If any existing CertificateRequest resources exist and are complete,
		// we delete them to avoid a re-issuance of the same certificate.
		if !metav1.IsControlledBy(&req, &cert) {
			continue
		}

		// This indicates an issuance is currently in progress
		if len(req.Status.Certificate) == 0 {
			log.Printf("Found existing CertificateRequest %s/%s for Certificate - skipping triggering a renewal...", req.Namespace, req.Name)
			return nil
		}

		if err := cl.Delete(ctx, &req); err != nil {
			log.Printf("Failed to delete old CertificateRequest %s/%s for Certificate", req.Namespace, req.Name)
			return err
		}

		log.Printf("Deleted old CertificateRequest %s/%s for Certificate", req.Namespace, req.Name)
	}

	// Fetch an up to date copy of the Secret resource for this Certificate
	var secret core.Secret
	if err := cl.Get(ctx, client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}, &secret); err != nil {
		log.Printf("Failed to retrieve up-to-date copy of existing Secret resource for Certificate: %v", err)
		return err
	}

	// Manually override/set the IssuerNameAnnotationKey - this will cause cert-manager
	// to assume that we have changed the 'issuerRef' specified on the Certificate and
	// trigger a one-time renewal.
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[capi.IssuerNameAnnotationKey] = "force-renewal-triggered"
	if err := cl.Update(ctx, &secret); err != nil {
		log.Printf("Failed to update Secret resource for Certificate: %v", err)
		return err
	}

	log.Printf("Triggered renewal of Certificate - waiting for new CertificateRequest resource to be created...")
	// Wait for a CertificateRequest resource to be created
	err := wait.Poll(time.Second, time.Minute, func() (bool, error) {
		var requests capi.CertificateRequestList
		if err := cl.List(ctx, &requests, client.InNamespace(cert.Namespace)); err != nil {
			return false, err
		}
		// Wait for a CertificateRequest owned by this Certificate to exist
		for _, req := range requests.Items {
			if metav1.IsControlledBy(&req, &cert) {
				log.Printf("CertificateRequest %s/%s found, renewal in progress!", req.Namespace, req.Name)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		log.Printf("Failed to wait for new CertificateRequest to be created: %v", err)
		return err
	}
	return nil
}

func affectedCertificates(certsBySerial map[string]capi.Certificate) (map[string]capi.Certificate, error) {
	f, err := os.Open(affectedSerialsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	affectedMap := make(map[string]capi.Certificate)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "serial ") {
			log.Printf("Failed to parse line in affected serials file, does not start with 'serial ': %v", line)
			continue
		}

		// extract the serial number from the serials.txt file and convert it
		// to a big.Int to avoid trailing zeroes in serial numbers causing problems.
		serial := strings.Split(line, " ")[1]
		serialInt := big.NewInt(0)
		_, ok := serialInt.SetString(serial, 16)
		if !ok {
			log.Printf("Failed to parse int64 from serial number in serials.txt: %v (line: %s)", err, line)
			continue
		}
		cert, affected := certsBySerial[fmt.Sprintf("%x", serialInt)]
		if !affected {
			continue
		}
		affectedMap[serial] = cert
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return affectedMap, nil
}

func makeSecretsMap(secrets []core.Secret) map[string]core.Secret {
	m := make(map[string]core.Secret)
	for _, s := range secrets {
		m[s.Namespace+"/"+s.Name] = s
	}
	return m
}

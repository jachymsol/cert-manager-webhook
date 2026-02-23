package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	acmev1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&jachymsolDNSProviderSolver{},
	)
}

type jachymsolDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type jachymsolDNSProviderConfig struct {
	BaseUrl  string           `json:"baseUrl"`
	Username valueOrSecretRef `json:"username"`
	Password valueOrSecretRef `json:"password"`
	DomainId valueOrSecretRef `json:"domainId"`
}

type valueOrSecretRef struct {
	Value     string     `json:"value,omitempty"`
	SecretRef *secretRef `json:"secretRef,omitempty"`
}

type secretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func (c *jachymsolDNSProviderSolver) Name() string {
	return "jachymsol"
}

func (c *jachymsolDNSProviderSolver) Present(ch *acmev1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	config, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("unable to load config: %w", err)
	}

	client, err := c.getClient(config, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get client: %w", err)
	}

	// Publish the DNS record
	err = client.PublishRecord(ch.ResolvedFQDN, ch.Key)
	if err != nil {
		return fmt.Errorf("unable to publish record: %w", err)
	}

	klog.Infof("Presented txt record %v", ch.ResolvedFQDN)

	return nil
}

func (c *jachymsolDNSProviderSolver) CleanUp(ch *acmev1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function CleanUp: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	config, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("unable to load config: %w", err)
	}

	client, err := c.getClient(config, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get client: %w", err)
	}

	// Delete the DNS record
	err = client.DeleteRecord(ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("unable to delete record: %w", err)
	}

	klog.Infof("Deleted TXT record result: %v", string(ch.ResolvedFQDN))

	return nil
}

func (c *jachymsolDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	k8sClient, err := kubernetes.NewForConfig(kubeClientConfig)
	klog.V(6).Infof("Input variable stopCh is %d length", len(stopCh))
	if err != nil {
		return err
	}

	c.client = k8sClient

	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (jachymsolDNSProviderConfig, error) {
	cfg := jachymsolDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *jachymsolDNSProviderSolver) getClient(cfg jachymsolDNSProviderConfig, namespace string) (client *DnsClient, err error) {
	username, err := c.resolveValueOrFromSecret(cfg.Username, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	password, err := c.resolveValueOrFromSecret(cfg.Password, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	domainId, err := c.resolveValueOrFromSecret(cfg.DomainId, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	dnsClient, err := NewDnsClient(DnsClientConfig{
		DnsClientBaseUrl:  cfg.BaseUrl,
		DnsClientUsername: username,
		DnsClientPassword: password,
		DnsClientDomainId: domainId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return dnsClient, nil
}

func (c *jachymsolDNSProviderSolver) resolveValueOrFromSecret(vsr valueOrSecretRef, namespace string) (value string, err error) {
	if vsr.SecretRef != nil {
		secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), vsr.SecretRef.Name, metav1.GetOptions{})

		if err != nil {
			return "", fmt.Errorf("unable to get secret %s: %w", vsr.SecretRef.Name, err)
		}

		secBytes, ok := secret.Data[vsr.SecretRef.Key]
		if !ok {
			return "", fmt.Errorf("key %q not found in secret %s: %w", vsr.SecretRef.Key, vsr.SecretRef.Name, err)
		}

		return string(secBytes), nil
	}
	return vsr.Value, nil
}

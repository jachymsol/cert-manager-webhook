package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const (
	TEMPLATE_ENDPOINT_LOGIN             = "/login.php?username=%s&password=%s&action=login&lang=cs"
	TEMPLATE_ENDPOINT_GET_RECORDS       = "/index.php?page=domeny-dns&id_domain=%s"
	TEMPLATE_ENDPOINT_ADD_TXT_RECORD    = "/index.php?sub=%s&txt=%s&page=domany-dns-txt-add&action=txt_add&id_domain=%s"
	TEMPLATE_ENDPOINT_DELETE_TXT_RECORD = "/index.php?page=domeny-dns&action=txt_delete&id_domain=%s&id=%s"
)

type DnsClient struct {
	baseUrl    string
	username   string
	password   string
	domainId   string
	httpClient *http.Client
}

type DnsClientConfig struct {
	DnsClientBaseUrl  string
	DnsClientUsername string
	DnsClientPassword string
	DnsClientDomainId string
}

func NewDnsClient(config DnsClientConfig) (*DnsClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Jar: jar,
	}

	return &DnsClient{
		baseUrl:    config.DnsClientBaseUrl,
		username:   config.DnsClientUsername,
		password:   config.DnsClientPassword,
		domainId:   config.DnsClientDomainId,
		httpClient: client,
	}, nil
}

func (c *DnsClient) PublishRecord(domain string, txt string) error {
	// Call Login to get session cookies
	if err := c.login(); err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	// Extract subdomain from full domain name
	domainParts := strings.Split(domain, ".")
	sub := strings.Join(domainParts[:len(domainParts)-2], ".")

	// Call addTxtRecord with the obtained cookies
	return c.addTxtRecord(sub, txt)
}

func (c *DnsClient) DeleteRecord(domain string) error {
	// Call Login to get session cookies
	if err := c.login(); err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	// Call getRecords to retrieve all records
	doc, err := c.getRecords()
	if err != nil {
		return fmt.Errorf("failed to get records: %w", err)
	}

	// Find the correct node with the record
	found, recordId, err := findTxtRecordId(doc, domain)
	if err != nil || !found {
		return fmt.Errorf("failed to find recordId in records page: %w", err)
	}

	if recordId == "" {
		return fmt.Errorf("record not found for domain: %s", domain)
	}

	// Call deleteTxtRecord with the found record ID
	return c.deleteTxtRecord(recordId)
}

func (c *DnsClient) login() error {
	loginUrl := c.baseUrl + url.PathEscape(fmt.Sprintf(TEMPLATE_ENDPOINT_LOGIN, c.username, c.password))

	resp, err := c.httpClient.Get(loginUrl)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add record failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *DnsClient) addTxtRecord(sub string, txt string) error {
	addUrl := c.baseUrl + url.PathEscape(fmt.Sprintf(TEMPLATE_ENDPOINT_ADD_TXT_RECORD, sub, txt, c.domainId))

	req, err := http.NewRequest("GET", addUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create add record request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add record request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add record failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

type DnsRecord struct {
	RecordId   string `json:"record_id"`
	DomainName string `json:"domain_name"`
	TextField  string `json:"text_field"`
}

func (c *DnsClient) getRecords() (*html.Node, error) {
	getUrl := c.baseUrl + url.PathEscape(fmt.Sprintf(TEMPLATE_ENDPOINT_GET_RECORDS, c.domainId))

	req, err := http.NewRequest("GET", getUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get records request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get records request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get records failed with status %d: %s", resp.StatusCode, string(body))
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML from response body: %w", err)
	}

	return doc, nil
}

func findTxtRecordId(node *html.Node, domain string) (found bool, recordId string, err error) {
	// If node == <td data-title="TXT záznam"> && node.PrevSibling == <td><strong>{domain}</strong></td>
	if isTxtRowNode(node) {
		nodeDomain, err := getTxtNodeDomain(node.PrevSibling)
		if err != nil {
			return false, "", err
		}

		if nodeDomain == domain {
			// node.NextSibling is <td><a href="...">, return the parsed recordId from href
			recordId, err := getRecordIdFromNodeDomain(node.NextSibling)
			if err != nil {
				return false, "", err
			}

			return true, recordId, nil
		}
	}

	// Traverse child nodes
	for childNode := node.FirstChild; childNode != nil; childNode = childNode.NextSibling {
		found, txtNode, err := findTxtRecordId(childNode, domain)
		if err != nil || found {
			return found, txtNode, nil
		}
	}
	return false, "", nil
}

// isTxtRowNode is a helper function to determine if node == <td data-title="TXT záznam">
func isTxtRowNode(node *html.Node) bool {
	if node.Type == html.ElementNode && node.Data == "td" {
		for _, a := range node.Attr {
			if a.Key == "data-title" {
				return a.Val == "TXT záznam"
			}
		}
	}

	return false
}

// getTxtNodeDomain is a helper function to retrieve domain from node of type <td><strong>{domain}</strong></td>
func getTxtNodeDomain(tdNode *html.Node) (string, error) {
	strongNode := tdNode.FirstChild
	if strongNode == nil {
		return "", fmt.Errorf("unexpected node structure, tdNode with txt record has no child")
	}

	domainNode := strongNode.FirstChild
	if domainNode == nil {
		return "", fmt.Errorf("unexpected node structure, strongNode with txt record has no child")
	}

	if domainNode.Type == html.TextNode {
		return domainNode.Data, nil
	}

	return "", fmt.Errorf("unexpected node structure, domainNode with txt record is not of type TextNode, but %T", domainNode.Type)
}

func getRecordIdFromNodeDomain(tdNode *html.Node) (string, error) {
	aNode := tdNode.FirstChild
	if aNode == nil {
		return "", fmt.Errorf("unexpected node structure, tdNode with txt record has no child")
	}

	for _, a := range aNode.Attr {
		if a.Key == "href" {
			hrefChunks := strings.Split(a.Val, "'")
			if len(hrefChunks) != 3 {
				return "", fmt.Errorf("unexpected href format does not contain the correct number of ' in %s", a.Val)
			}
			path := hrefChunks[1]

			recordIdIndex := strings.Index(path, "id=")
			if recordIdIndex == -1 {
				return "", fmt.Errorf("failed to find id= in href %s", path)
			}
			return path[recordIdIndex+3:], nil
		}
	}

	return "", fmt.Errorf("failed to find href attribute in aNode")
}

func (c *DnsClient) deleteTxtRecord(recordId string) error {
	deleteUrl := c.baseUrl + url.PathEscape(fmt.Sprintf(TEMPLATE_ENDPOINT_DELETE_TXT_RECORD, c.domainId, recordId))

	req, err := http.NewRequest("GET", deleteUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete record request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete record request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete record failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

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
	ENDPOINT_LOGIN = "login.php"
	ENDPOINT_INDEX = "index.php"

	TEMPLATE_SEARCH_PARAMS_GET_RECORDS       = "page=domeny-dns&id_domain=%s"
	TEMPLATE_SEARCH_PARAMS_DELETE_TXT_RECORD = "page=domeny-dns&action=txt_delete&id_domain=%s&id=%s"
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

	// Remove last "." if included
	readableDomain := strings.Trim(domain, ".")

	// Extract subdomain from full domain name
	domainParts := strings.Split(readableDomain, ".")
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

	// Remove last "." if included
	readableDomain := strings.Trim(domain, ".")

	// Find the correct node with the record
	found, recordId, err := findTxtRecordId(doc, readableDomain)
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
	loginUrl := fmt.Sprintf("%s/%s", c.baseUrl, ENDPOINT_LOGIN)

	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", c.password)
	form.Set("action", "login")
	form.Set("lang", "cs")

	resp, err := c.httpClient.PostForm(loginUrl, form)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add record failed with status %d, expected %d: %s", resp.StatusCode, http.StatusFound, string(body))
	}

	return nil
}

func (c *DnsClient) addTxtRecord(sub string, txt string) error {
	addUrl := fmt.Sprintf("%s/%s", c.baseUrl, ENDPOINT_INDEX)

	form := url.Values{}
	form.Set("sub", sub)
	form.Set("txt", txt)
	form.Set("page", "domeny-dns-txt-add")
	form.Set("action", "txt_add")
	form.Set("id_domain", c.domainId)

	resp, err := c.httpClient.PostForm(addUrl, form)
	if err != nil {
		return fmt.Errorf("add record request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add record failed with status %d, expected %d: %s", resp.StatusCode, http.StatusFound, string(body))
	}

	return nil
}

func (c *DnsClient) getRecords() (*html.Node, error) {
	searchParams := url.PathEscape(fmt.Sprintf(TEMPLATE_SEARCH_PARAMS_GET_RECORDS, c.domainId))
	getUrl := fmt.Sprintf("%s/%s?%s", c.baseUrl, ENDPOINT_INDEX, searchParams)

	resp, err := c.httpClient.Get(getUrl)
	if err != nil {
		return nil, fmt.Errorf("get records request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get records failed with status %d, expected 200: %s", resp.StatusCode, string(body))
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML from response body: %w", err)
	}

	return doc, nil
}

// findTxtRecordId is a helper function which, given a root node of a document and a domain, finds the recordId of the TXT record associated with this domain
func findTxtRecordId(node *html.Node, domain string) (found bool, recordId string, err error) {
	// If node == <td data-title="TXT záznam"> && node.PrevSibling == <td><strong>{domain}</strong></td>
	if isTxtRowNode(node) {
		nodeDomain, err := getTxtNodeDomain(node)
		if err != nil {
			return false, "", err
		}

		if nodeDomain == domain {
			// node.NextSibling is <td><a href="...">, return the parsed recordId from href
			recordId, err := getRecordIdFromNodeDomain(node)
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
			return found, txtNode, err
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

// getTxtNodeDomain is a helper function to retrieve domain from node of type <td><strong>{domain}</strong></td><td data-title="TXT záznam"/>
func getTxtNodeDomain(txtTdNode *html.Node) (string, error) {
	domainTdNode := txtTdNode.PrevSibling
	for domainTdNode != nil && domainTdNode.Type != html.ElementNode {
		domainTdNode = domainTdNode.PrevSibling
	}
	if domainTdNode == nil {
		return "", fmt.Errorf("unexpected node structure, tdNode with txt record does not have a td prevSibling")
	}

	strongNode := domainTdNode.FirstChild
	if strongNode == nil || strongNode.Type != html.ElementNode || strongNode.Data != "strong" {
		return "", fmt.Errorf("unexpected node structure, tdNode with domain for txt record has no child with tag <strong>")
	}

	domainNode := strongNode.FirstChild
	if domainNode == nil || domainNode.Type != html.TextNode {
		return "", fmt.Errorf("unexpected node structure, strongNode with domain for txt record has no child of type TextNode")
	}

	return domainNode.Data, nil
}

// getRecordIdFromNodeDomain is a helper function to retrieve the recordId from node of type <td data-title="TXT záznam"/><td><a href="index.php?recordId={id}.../>"
func getRecordIdFromNodeDomain(txtTdNode *html.Node) (string, error) {
	aTdNode := txtTdNode.NextSibling
	for aTdNode != nil && aTdNode.Type != html.ElementNode {
		aTdNode = aTdNode.NextSibling
	}
	if aTdNode == nil {
		return "", fmt.Errorf("unexpected node structure, tdNode with txt record does not have a td nextSibling")
	}

	aNode := aTdNode.FirstChild
	if aNode == nil || aNode.Type != html.ElementNode || aNode.Data != "a" {
		return "", fmt.Errorf("unexpected node structure, tdNode with txt record has no child with tag <a>")
	}

	for _, a := range aNode.Attr {
		if a.Key == "href" {
			hrefChunks := strings.Split(a.Val, "'")
			if len(hrefChunks) != 3 {
				return "", fmt.Errorf("unexpected href format does not contain the correct number of ' in %s", a.Val)
			}
			path := hrefChunks[1]

			_, after, ok := strings.Cut(path, "id=")
			if !ok {
				return "", fmt.Errorf("failed to find id= in href %s", path)
			}
			return after, nil
		}
	}

	return "", fmt.Errorf("failed to find href attribute in aNode")
}

func (c *DnsClient) deleteTxtRecord(recordId string) error {
	searchParams := url.PathEscape(fmt.Sprintf(TEMPLATE_SEARCH_PARAMS_DELETE_TXT_RECORD, c.domainId, recordId))
	deleteUrl := fmt.Sprintf("%s/%s?%s", c.baseUrl, ENDPOINT_INDEX, searchParams)

	resp, err := c.httpClient.Get(deleteUrl)
	if err != nil {
		return fmt.Errorf("delete record request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete record failed with status %d, expected %d: %s", resp.StatusCode, http.StatusFound, string(body))
	}

	return nil
}

package vk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	//actual version
	apiVersion     = "5.27"
	//url for authorization
	authUrl        = "https://oauth.vk.com/authorize"
	//url for get access token
	accessTokenUrl = "https://oauth.vk.com/access_token"
	//url for execute methods
	methodUrl      = "https://api.vk.com/method/"
)

// main type of package
type Api struct {
	AccessToken AccessToken
}

// OAuth
type Auth struct {
	AppId       string
	AppSecret   string
	Permissions []string
	RedirectUri string
	Display     string
}

// Security token
type AccessToken struct {
	Token     string `json:"access_token"`
	ExpiresIn int64  `json:"expires_in"`
	UserId    int64  `json:"user_id"`
}

// Typical vk.com error contains two fields - error, error_description.
// And that's great.
type AccessError struct {
	Summary     string `json:"error"`
	Description string `json:"error_description"`
}

func (e AccessError) Error() string {
	return fmt.Sprintf("%s: %s", e.Summary, e.Description)
}

// Get authorization url for user redirection, more:
// https://vk.com/dev/auth_sites
func (auth Auth) GetAuthUrl() (string, error) {
	urlPieces, err := url.Parse(authUrl)
	if err != nil {
		return "", err
	}

	query := urlPieces.Query()

	query.Set("client_id", auth.AppId)
	query.Set("scope", strings.Join(auth.Permissions, ","))
	query.Set("redirect_uri", auth.RedirectUri)
	query.Set("display", auth.Display)
	query.Set("response_type", "code")

	urlPieces.RawQuery = query.Encode()

	return urlPieces.String(), nil
}

// Get access token for 'Server Auth'
func (auth Auth) GetAccessToken(code string) (AccessToken, error) {
	urlPieces, err := url.Parse(authUrl)
	if err != nil {
		return AccessToken{}, err
	}

	query := urlPieces.Query()

	query.Set("client_id", auth.AppId)
	query.Set("client_secret", auth.AppSecret)
	query.Set("code", code)
	query.Set("redirect_uri", auth.RedirectUri)

	urlPieces.RawQuery = query.Encode()

	resp, err := http.Get(urlPieces.String())
	if err != nil {
		return AccessToken{}, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	accessToken := AccessToken{}
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		return AccessToken{}, err
	}

	//may be error?
	if accessToken.ExpiresIn == 0 {
		//okay, something is wrong...
		//may be it's simple Error?
		accessError := AccessError{}
		err = json.Unmarshal(body, &accessError)
		if err != nil {
			return AccessToken{}, err
		}

		//okay we are have problems with authorization...
		if accessError.Summary != "" {
			return AccessToken{}, accessError
		}
	} else {
		return accessToken, nil
	}

	return AccessToken{}, errors.New(fmt.Sprintf(
		"Couldn't recognize error, body: %s", body))
}

// do you want make a request? It's it.
func (api *Api) Request(method string, params map[string]string) (
	map[string]interface{}, error) {
	result := map[string]interface{}{}

	urlPieces, err := url.Parse(methodUrl + method)
	if err != nil {
		return result, err
	}

	query := urlPieces.Query()
	for name, value := range params {
		query.Set(name, value)
	}

	query.Set("access_token", api.AccessToken.Token)
	query.Set("version", apiVersion)

	urlPieces.RawQuery = query.Encode()

	resp, err := http.Get(urlPieces.String())
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(body, &result)
	//may be catch {"error":{"error_code":15...blahblah?
	return result, err
}

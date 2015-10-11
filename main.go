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
	apiVersion = "5.27"

	//url for authorization
	authUrl = "https://oauth.vk.com/authorize"

	//url for get access token
	accessTokenUrl = "https://oauth.vk.com/access_token"

	//url for execute methods
	methodUrl = "https://api.vk.com/method/"
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

// you can specify pkg logger for debug library
type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

var logger Logger

func SetLogger(l Logger) {
	logger = l
}

func logf(format string, v ...interface{}) {
	if logger != nil {
		logger.Printf(format, v...)
	}
}

// Get authorization url for user redirection, more:
// https://vk.com/dev/auth_sites
func (auth Auth) GetAuthUrl() (string, error) {
	logf("processing GetAuthUrl of %+v", auth)

	logf("trying to parse '%s'", authUrl)
	urlPieces, err := url.Parse(authUrl)
	if err != nil {
		logf("an error occured during parsing url: %s", err)
		return "", err
	}

	query := urlPieces.Query()

	query.Set("client_id", auth.AppId)
	query.Set("scope", strings.Join(auth.Permissions, ","))
	query.Set("redirect_uri", auth.RedirectUri)
	query.Set("display", auth.Display)
	query.Set("response_type", "code")

	logf("auth url query: %+v", query)
	urlPieces.RawQuery = query.Encode()

	authUrl := urlPieces.String()
	logf("auth url: '%s'", authUrl)

	return authUrl, nil
}

// Get access token for 'Server Auth'
func (auth Auth) GetAccessToken(code string) (accessToken AccessToken, err error) {
	logf("processing GetAccessToken of %+v", auth)

	logf("trying to parse '%s'", accessTokenUrl)
	urlPieces, err := url.Parse(accessTokenUrl)
	if err != nil {
		logf("an error occured during parsing url: %s", err)
		return
	}

	query := urlPieces.Query()

	query.Set("client_id", auth.AppId)
	query.Set("client_secret", auth.AppSecret)
	query.Set("code", code)
	query.Set("redirect_uri", auth.RedirectUri)

	urlPieces.RawQuery = query.Encode()
	logf("access token url query: %+v", query)

	tokenUrl := urlPieces.String()

	logf("trying to get content of '%s'", tokenUrl)
	resp, err := http.Get(tokenUrl)
	if err != nil {
		logf("an error occured during execution GET request: %s", err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	logf("received content: %s", body)

	logf("trying to unmarshal response to accessToken struct")
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		logf("an error occured during json decoding: %s", err)
		return
	}

	logf("unmarshaled data (accessToken): %+v", accessToken)

	if accessToken.ExpiresIn != 0 {
		logf("all is ok, accessToken: %+v", accessToken)
		return
	}

	//okay, something is wrong... may be it's typical error?
	logf("accessToken.ExpiresIn = 0, trying recognize error")
	accessError := AccessError{}
	err = json.Unmarshal(body, &accessError)
	if err != nil {
		logf("an error occured during json decoding: %s", err)
		return
	}

	logf("unmarshaled data (accessError): %+v", accessToken)

	//okay we are have problems with authorization...
	if accessError.Summary != "" {
		logf("problem with a getting access: %s", accessError)
		return AccessToken{}, accessError
	}

	logf("couldn't recognize error")

	return AccessToken{}, errors.New(fmt.Sprintf(
		"Couldn't recognize error, body: %s", body))
}

// do you want make a request? It's it.
func (api *Api) Request(method string, params map[string]string) (
	response map[string]interface{}, err error) {

	logf("proccessing request method '%s' with params %+v of api %+v",
		method, params, api)

	rawUrl := methodUrl + method

	logf("raw url for execution method is '%s'", rawUrl)

	urlPieces, err := url.Parse(rawUrl)
	if err != nil {
		logf("an error occured during parsing url: %s", err)
		return
	}

	logf("begin to prepare the data for the request")

	query := urlPieces.Query()
	for name, value := range params {
		query.Set(name, value)
	}

	logf("query w/o access_token and version: %+v", query)

	if api.AccessToken.Token != "" {
		query.Set("access_token", api.AccessToken.Token)
	}

	query.Set("version", apiVersion)

	logf("query with access_token and version: %+v", query)

	urlPieces.RawQuery = query.Encode()

	resultUrl := urlPieces.String()
	logf("trying to get content of '%s'", resultUrl)
	resp, err := http.Get(resultUrl)
	if err != nil {
		logf("an error occured during execution GET request: %s", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logf("an error occured during reading body buffer: %s", err)
		return
	}

	logf("received: %s:", body)

	err = json.Unmarshal(body, &response)
	if err != nil {
		logf("an error occured during json decoding: %s", err)
	} else {
		logf("response: %+v", response)
	}

	//may be catch {"error":{"error_code":15...blahblah?
	return
}

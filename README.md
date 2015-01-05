# Intro

This is package for work with vk.com API.

Basically, it helps with authorzation (vk.com uses OAuth).

# Usage

## Authorization

Basically, you need to read this article: https://vk.com/dev/auth_sites

First, you need app domain, app id and app secret (yep, you are can get
this on settings page in your app in vk.com)

Second, you need a list of permissions that you want to get.

Create instance of `vk.Auth`:

```go

auth := vk.Auth{
    AppId: "your_app_id",
    AppSecret: "your_app_secret",
    Permissions: []string{"audio"},
    RedirectUri: "http://yourhost.local/",
    Display: "page", // more on https://vk.com/dev/auth_sites
}

```

Then you need to get url for user auth.

```go
authUrl, err := auth.GetAuthUrl()
if err != nil {
	panic(err)
}

fmt.Printf(authUrl)
```

Next, you need to redirect the user to `authUrl`.

After the user allows your app, he will come back with the code
parameter. (`http://yourhost.local/?code=somelongsha256`)

Good time to get access token.

```go
// `code` is param of url query.
token, err := auth.GetAccessToken(code)
if err != nil {
	panic(err)
}
```

If all is ok, you should create instance of `vk.Api` and provide him of token.

```go
api := vk.Api{token}
```

Fine, we have everything to make requests.

For example, look for `Burzum` tracks.

```go
query := map[string]string{
	"q": "Burzum",
}

response, err := api.Request("audio.search", query)
if err != nil {
	panic(err)
}

fmt.Printf("%+v", response)
```

# Tricks

You can enable logging in library.

```go
    vk.SetLogger(
        log.New(os.Stdout, "VK: ", log.Ldate|log.Ltime|log.Lshortfile))
```

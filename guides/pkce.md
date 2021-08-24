# Notes for pkce extension

## Prerequisites
There are a few pre-requisites.

Have a way to inject `:current_user` in the conn, otherwise implement it before continuing, also keep in mind that in most cases the `:current_user` is the same as the resource owner on OAuth.

On our server, we need to create a client with pkce value as true.

```elixir
alias Boruta.Ecto.Admin.Clients
{:ok, client} = %{authorization_code_ttl: 60, access_token_ttl: 60 * 60, pkce: true, name: "My Awesome Client App", redirect_uris: ["http://localhost:4000"]} |> Clients.create_client()
```

We will get the `client.id` among others fields.


## Flow steps
From the client perspective, who is in charge of sending the `code_challenge` and `code_challenge_method` among other fields during the request of the code, there is a `code_verifier` variable which is a key concept to keep in mind because `code_challenge` depends on it and also depends on `code_challenge_method`, let's see an example.

In our client, we must have an URL to request the `/oauth/authorize` endpoint to get the code. To build the URL we should follow a similar approach to the proposed.
```elixir
client_id = client.id
code_verifier = "a-strong-random-string"
state = "a-random-verifiable-state-on-client"
# When the code challenge method is S256, we must follow the standard code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
code_challenge_method = "S256"
code_challenge = :crypto.hash(:sha256, code_verifier) |> Base.url_encode64()
# Only if our client does not support sha256 crypto it goes through the plain method. Then code_challenge = code_verifier
#
# Keep in mind that it must be used only if your architecture does not support Sha256 crypto. otherwise use it.
#
# code_challenge_method = "plain"
# code_challenge = code_verifier

# Then we are ready to build your URL.

url = "http://localhost:4000/oauth/authorize?response_type=code&client_id=#{client_id}&redirect_uri=http://localhost:4000&state=#{state}&code_challenge=#{code_challenge}=&code_challenge_method=#{code_challenge_method}"

"http://localhost:4000/oauth/authorize?response_type=code&client_id=client-id&redirect_uri=http://localhost:4000&state=a-random-verifiable-state-on-client&code_challenge=PdSbV6nNRlruDAqmULREHO_pLwfmNnNGA-HGIjmc6VA==&code_challenge_method=S256"

```

You can paste the URL in your browser with a logged user and retrieve the code from the response URL.

Having the code the next step is to retrieve a token, in this case, the client must call the `oauth/token` to get it.

Based on the previous step, a request example could look like this.

```bash
curl --location --request POST 'http://localhost:4000/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'client_id=c96951c5c-f7b5-4d03-ac09-657833d113df' \
--data-urlencode 'code=4vlPc010GKutGlCYeT3VZFbyoVewmtNPOo0c5DXvt1iQ9pBd0BkeCutVwHWFNq8vzdTfIPppFGlhuYuOIWtvnU' \
--data-urlencode 'code_verifier=a-strong-random-string' \
--data-urlencode 'redirect_uri=http://localhost:4000' \
--data-urlencode 'state=a-random-verifiable-state-on-client'
```

It's important to notice that the code_verifier has the value previously generated and is not encrypted. This is because the server knows that you use encrypted method S256,
and it implements the logic to handle it.

And that is all. If your configuration is right, you will get a response like this.

```json
{"access_token":"BHYQabRwti673RVhoMnqXtrvgiEilawgaAj1KosrQV9pGQ4DBENXzhUHeSjZE4K02S8bNtlNL2gU9bzFhKMoQK","expires_in":3600,"refresh_token":"r90e4S9uaqH59xMO809Ws2uzWPtcaMlcF1J7fcaaSruE1AAc30WuykNAL73GGNECtmYezQSf2CzJGgQWPqdM5M","token_type":"bearer"}
```

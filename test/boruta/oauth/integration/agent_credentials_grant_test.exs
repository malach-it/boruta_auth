defmodule Boruta.OauthTest.AgentCredentialsGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Ecto.ScopeStore
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.TokenResponse

  describe "agent credentials grant" do
    setup do
      client = insert(:client)
      dpop_client = insert(:client, enforce_dpop: true)
      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          authorize_scope: true,
          authorized_scopes: [
            insert(:scope, name: "public", public: true),
            insert(:scope, name: "private", public: false)
          ]
        )

      {:ok,
       client: client,
       dpop_client: dpop_client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type}
    end

    test "returns an error if `grant_type` is 'agent_credentials' and schema is invalid" do
      assert Oauth.token(
               %Plug.Conn{body_params: %{"grant_type" => "agent_credentials"}},
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required property client_id is missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if client_id/secret are invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_credentials",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "client_secret" => "client_secret"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns an error if secret is invalid", %{client: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_credentials",
                   "client_id" => client.id,
                   "client_secret" => "bad_client_secret"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns an error when dpop is malformed", %{dpop_client: client} do
      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "DPoP header malformed: :token_malformed",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", "malformed dpop"}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop jwt header is missing", %{dpop_client: client} do
      signer = Joken.Signer.create("HS512", "secret")
      {:ok, dpop, _claims} = Token.encode_and_sign(%{}, signer)

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "Missing required JWT headers in DPoP.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop is signed with symetric alg", %{dpop_client: client} do
      signer =
        Joken.Signer.create("HS512", "secret", %{
          "jwk" => :jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} = Token.encode_and_sign(%{}, signer)

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "DPoP must be signed with an asymetric algorithm.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop signature is malformed", %{dpop_client: client} do
      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => :jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} = Token.encode_and_sign(%{}, signer)

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "Could not validate DPoP header.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop signature is invalid", %{dpop_client: client} do
      {_, jwk} = JOSE.JWK.from_pem(other_valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} = Token.encode_and_sign(%{}, signer)

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "Invalid DPoP signature: :signature_error",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop claims are missing", %{dpop_client: client} do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} = Token.encode_and_sign(%{}, signer)

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "`htm` or `htu` claims missing in DPoP header JWT.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop method is invalid", %{dpop_client: client} do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} =
        Token.encode_and_sign(
          %{
            "htu" => "htu",
            "htm" => "GET"
          },
          signer
        )

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "DPoP allowed method does not match request.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   method: "POST",
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error when dpop url is invalid", %{dpop_client: client} do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} =
        Token.encode_and_sign(
          %{
            "htu" => "htu",
            "htm" => "POST"
          },
          signer
        )

      assert {:token_error,
              %Error{
                error: :bad_request,
                error_description: "DPoP allowed URL does not match request.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   host: "host",
                   method: "POST",
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error with invalid bind data", %{client: client} do
      assert {
               :token_error,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description:
                   "Invalid bind parameter: unexpected byte at position 0: 0x69 (\"i\")",
                 format: nil,
                 redirect_uri: nil,
                 state: nil,
                 status: :bad_request
               }
             } =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "bind_data" => "invalid",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns an error with invalid bind configuration", %{client: client} do
      assert {
               :token_error,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description:
                   "Invalid bind parameter: unexpected byte at position 0: 0x69 (\"i\")",
                 format: nil,
                 redirect_uri: nil,
                 state: nil,
                 status: :bad_request
               }
             } =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "bind_data" => "{}",
                     "bind_configuration" => "invalid"
                   }
                 },
                 ApplicationMock
               )
    end

    test "returns a token when dpop is valid", %{dpop_client: client} do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} =
        Token.encode_and_sign(
          %{
            "htu" => "http://host/pa/th",
            "htm" => "POST"
          },
          signer
        )

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   host: "host",
                   request_path: "pa/th",
                   method: "POST",
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token", %{client: client} do
      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token with public scope", %{client: client} do
      given_scope = "public"

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "scope" => given_scope,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token with public scope (from cache)", %{client: client} do
      given_scope = "public"
      ScopeStore.put_public([%Scope{name: "public"}])

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "scope" => given_scope,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns an error with private scope", %{client: client} do
      given_scope = "private"

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Boruta.Oauth.Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  format: nil,
                  redirect_uri: nil,
                  status: :bad_request
                }}
    end

    test "returns a token if scope is authorized", %{client_with_scope: client} do
      %{name: given_scope} = List.first(client.authorized_scopes)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "scope" => given_scope,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns an error if scopes are unknown or unauthorized", %{client_with_scope: client} do
      given_scope = "bad_scope"

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed", %{client_without_grant_type: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => ""
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :unsupported_grant_type,
                  error_description: "Client do not support given grant type.",
                  status: :bad_request
                }}
    end
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end

  def other_valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN0Mhw3A4JqMERW8ObFDLBYOMnmIDo3BJo9h8OYGlahXeCt1rvoNNHnN\no3lRy6nasZR4CE+brZHU9qq9Nukoyy6+qBddidwQ3Sh3T98GqCh8IEWh0F84i8ZA\noVXURCS+s4I/SbA7JjiS3zvwjUklk55fGm90jEArzF+JUH2LsSGFAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
  end
end

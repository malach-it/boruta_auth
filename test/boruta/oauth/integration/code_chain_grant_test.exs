defmodule Boruta.OauthTest.CodeChainGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Ecto
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.TokenResponse
  alias Boruta.Repo
  alias Boruta.Support.ResourceOwners

  setup :verify_on_exit!

  describe "code chain grant" do
    setup do
      client = insert(:client)
      client_without_grant_type = insert(:client, supported_grant_types: [])

      {:ok, client: client, client_without_grant_type: client_without_grant_type}
    end

    test "returns an error if schema is invalid" do
      assert Oauth.token(
               %Plug.Conn{body_params: %{"grant_type" => "code_chain"}},
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required properties client_id, id_token are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed", %{client_without_grant_type: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "code_chain",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "id_token" => id_token(client, "agent")
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

    test "issues an authorization code from an id_token", %{client: client} do
      id_token = id_token(client, "agent")

      ResourceOwners
      |> expect(:get_by, fn id_token: ^id_token, scope: nil ->
        {:ok, %ResourceOwner{sub: "agent"}}
      end)

      assert {:token_success,
              %TokenResponse{
                authorization_code: authorization_code,
                access_token: nil,
                refresh_token: nil
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "code_chain",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "id_token" => id_token
                   }
                 },
                 ApplicationMock
               )

      assert %Ecto.Token{
               type: "code",
               value: ^authorization_code,
               sub: "agent",
               id_token: ^id_token,
               redirect_uri: nil,
               nonce: nil,
               scope: "",
               previous_code: nil
             } = Repo.get_by(Ecto.Token, value: authorization_code)
    end

    test "chains a new authorization code from a previous authorization code", %{client: client} do
      first_id_token = id_token(client, "first-agent")
      second_id_token = id_token(client, "second-agent")

      ResourceOwners
      |> expect(:get_by, fn id_token: ^first_id_token, scope: nil ->
        {:ok, %ResourceOwner{sub: "first-agent"}}
      end)

      {:token_success, %TokenResponse{authorization_code: previous_authorization_code}} =
        Oauth.token(
          %Plug.Conn{
            body_params: %{
              "grant_type" => "code_chain",
              "client_id" => client.id,
              "client_secret" => client.secret,
              "id_token" => first_id_token
            }
          },
          ApplicationMock
        )

      ResourceOwners
      |> expect(:get_by, fn id_token: ^second_id_token, scope: nil ->
        {:ok, %ResourceOwner{sub: "second-agent"}}
      end)

      assert {:token_success, %TokenResponse{authorization_code: authorization_code}} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "code_chain",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "id_token" => second_id_token,
                     "authorization_code" => previous_authorization_code
                   }
                 },
                 ApplicationMock
               )

      assert %Ecto.Token{
               type: "code",
               value: ^authorization_code,
               sub: "second-agent",
               id_token: ^second_id_token,
               redirect_uri: nil,
               nonce: nil,
               previous_code: ^previous_authorization_code
             } = Repo.get_by(Ecto.Token, value: authorization_code)
    end

    test "takes scope from request parameters" do
      client =
        insert(:client,
          authorize_scope: true,
          authorized_scopes: [insert(:scope, name: "credential:read")]
        )

      id_token = id_token(client, "agent")

      ResourceOwners
      |> expect(:get_by, fn id_token: ^id_token, scope: "credential:read" ->
        {:ok, %ResourceOwner{sub: "agent"}}
      end)
      |> expect(:authorized_scopes, fn _resource_owner ->
        [%Oauth.Scope{name: "credential:read"}]
      end)

      assert {:token_success, %TokenResponse{authorization_code: authorization_code}} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "code_chain",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "id_token" => id_token,
                     "scope" => "credential:read"
                   }
                 },
                 ApplicationMock
               )

      assert %Ecto.Token{
               value: ^authorization_code,
               scope: "credential:read",
               nonce: nil
             } = Repo.get_by(Ecto.Token, value: authorization_code)
    end

    test "returns an error if id_token is invalid", %{client: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "code_chain",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "id_token" => "invalid"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "id_token must be a jwt.",
                  status: :bad_request
                }}
    end

    test "returns an error if id_token claims are missing", %{client: client} do
      assert_invalid_id_token(client, %{}, "id_token iat and exp are required.")
    end

    test "returns an error if id_token subject is missing", %{client: client} do
      now = :os.system_time(:second)

      assert_invalid_id_token(
        client,
        %{"iat" => now, "exp" => now + 60},
        "id_token sub is required."
      )
    end

    test "returns an error if id_token is expired", %{client: client} do
      now = :os.system_time(:second)

      assert_invalid_id_token(
        client,
        %{"sub" => "agent", "iat" => now - 120, "exp" => now - 60},
        "id_token is expired."
      )
    end

    test "returns an error if id_token iat is in the future", %{client: client} do
      now = :os.system_time(:second)

      assert_invalid_id_token(
        client,
        %{"sub" => "agent", "iat" => now + 60, "exp" => now + 120},
        "id_token iat must not be in the future."
      )
    end
  end

  defp assert_invalid_id_token(client, claims, description) do
    id_token = id_token(client, claims)

    assert {:token_error,
            %Error{
              error: :invalid_grant,
              error_description: ^description,
              status: :bad_request
            }} =
             Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "code_chain",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "id_token" => id_token
                 }
               },
               ApplicationMock
             )
  end

  defp id_token(client, sub) when is_binary(sub) do
    now = :os.system_time(:second)
    id_token(client, %{"sub" => sub, "iat" => now, "exp" => now + 60})
  end

  defp id_token(client, claims) when is_map(claims) do
    {_, jwk} = JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key}, %{"jwk" => jwk})

    {:ok, id_token, _claims} =
      Token.encode_and_sign(claims, signer)

    id_token
  end
end

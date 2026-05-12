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
      |> expect(:get_by, fn id_token: ^id_token -> {:ok, %ResourceOwner{sub: "agent"}} end)

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
               sub: ^id_token,
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
      |> expect(:get_by, fn id_token: ^first_id_token ->
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
      |> expect(:get_by, fn id_token: ^second_id_token ->
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
               sub: ^second_id_token,
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
      |> expect(:get_by, fn id_token: ^id_token -> {:ok, %ResourceOwner{sub: "agent"}} end)

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
                  error: :invalid_resource_owner,
                  error_description: "{:error, :token_malformed}",
                  status: :unauthorized
                }}
    end
  end

  defp id_token(client, sub) do
    {_, jwk} = JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key}, %{"jwk" => jwk})
    now = :os.system_time(:seconds)

    {:ok, id_token, _claims} =
      Token.encode_and_sign(
        %{
          "sub" => sub,
          "iat" => now,
          "exp" => now + 60
        },
        signer
      )

    id_token
  end
end

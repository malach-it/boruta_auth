defmodule Boruta.OauthTest.CodeChainGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Ecto
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.TokenResponse
  alias Boruta.Repo

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
                     "id_token" => id_token(client, "agent")
                   }
                 },
                 ApplicationMock
               )

      assert %Ecto.Token{
               type: "code",
               value: ^authorization_code,
               sub: "agent",
               redirect_uri: nil,
               previous_code: nil
             } = Repo.get_by(Ecto.Token, value: authorization_code)
    end

    test "chains a new authorization code from a previous authorization code", %{client: client} do
      {:token_success, %TokenResponse{authorization_code: previous_authorization_code}} =
        Oauth.token(
          %Plug.Conn{
            body_params: %{
              "grant_type" => "code_chain",
              "client_id" => client.id,
              "client_secret" => client.secret,
              "id_token" => id_token(client, "first-agent")
            }
          },
          ApplicationMock
        )

      assert {:token_success, %TokenResponse{authorization_code: authorization_code}} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "code_chain",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "id_token" => id_token(client, "second-agent"),
                     "authorization_code" => previous_authorization_code
                   }
                 },
                 ApplicationMock
               )

      assert %Ecto.Token{
               type: "code",
               value: ^authorization_code,
               sub: "second-agent",
               redirect_uri: nil,
               previous_code: ^previous_authorization_code
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

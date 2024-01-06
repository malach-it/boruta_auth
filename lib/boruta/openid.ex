defmodule Boruta.OpenidModule do
  @moduledoc false
  @callback jwks(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @callback userinfo(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @callback register_client(
              conn :: Plug.Conn.t() | map(),
              registration_params :: map(),
              module :: atom()
            ) :: any()
  @callback credential(
              conn :: Plug.Conn.t() | map(),
              credential_params :: map(),
              module :: atom()
            ) :: any()
end

defmodule Boruta.Openid do
  @moduledoc """
  Openid requests entrypoint, provides additional artifacts to OAuth as stated in [Openid Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

  > __Note__: this module follows inverted heaxagonal architecture, its functions will invoke callbacks of the given module argument and return its result.
  >
  > The definition of those callbacks are provided by either `Boruta.Openid.Application` or `Boruta.Openid.JwksApplication` and `Boruta.Openid.UserinfoApplication`
  """

  alias Boruta.ClientsAdapter
  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.BearerToken
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token
  alias Boruta.Openid.CredentialResponse
  alias Boruta.Openid.UserinfoResponse
  alias Boruta.VerifiableCredentials

  def jwks(conn, module) do
    jwk_keys = ClientsAdapter.list_clients_jwk()

    module.jwk_list(conn, jwk_keys)
  end

  def userinfo(conn, module) do
    with {:ok, access_token} <- BearerToken.extract_token(conn),
         {:ok, token} <- AccessToken.authorize(value: access_token),
         {:ok, userinfo} <- Token.userinfo(token) do
      module.userinfo_fetched(conn, UserinfoResponse.from_userinfo(userinfo, token.client))
    else
      {:error, error} ->
        module.unauthorized(conn, error)
    end
  end

  def register_client(conn, registration_params, module) do
    case registration_params
         |> parse_registration_params(registration_params)
         |> ClientsAdapter.create_client() do
      {:ok, client} ->
        module.client_registered(conn, client)

      {:error, changeset} ->
        module.registration_failure(conn, changeset)
    end
  end

  def credential(conn, credential_params, module) do
    with {:ok, access_token} <- BearerToken.extract_token(conn),
         {:ok, token} <- AccessToken.authorize(value: access_token),
         {:ok, credential_params} <- validate_credential_params(credential_params),
         {:ok, credential} <-
           VerifiableCredentials.issue_verifiable_credential(
             token.resource_owner,
             credential_params,
             token.client
           ) do
      response = CredentialResponse.from_credential(credential)
      module.credential_created(conn, response)
    else
      {:error, %Error{} = error} ->
        module.credential_failure(conn, error)

      {:error, reason} ->
        error = %Error{
          status: :bad_request,
          error: :invalid_request,
          error_description: reason
        }

        module.credential_failure(conn, error)
    end

    # TODO verify the proof https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-verifying-key-proof
    # TODO credential response
  end

  alias Boruta.Openid.Json.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  defp validate_credential_params(params) do
    case ExJsonSchema.Validator.validate(
           Schema.credential(),
           params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request body validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp parse_registration_params(params, %{jwks: %{"keys" => [jwk]}} = acc) do
    params =
      params
      |> Map.put(:jwk, jwk)
      |> Map.put(:token_endpoint_jwt_auth_alg, jwk["alg"])

    parse_registration_params(
      params,
      Map.delete(acc, :jwks)
    )
  end

  defp parse_registration_params(params, %{jwks_uri: jwks_uri} = acc) do
    with %URI{scheme: "" <> _scheme} <- URI.parse(jwks_uri),
         {:ok, %Finch.Response{body: jwks, status: 200}} <-
           Finch.build(:get, jwks_uri) |> Finch.request(OpenIDHttpClient),
         {:ok, %{"keys" => [jwk]}} <- Jason.decode(jwks, keys: :strings) do
      params =
        params
        |> Map.put(:jwk, jwk)
        |> Map.put(:jwks_uri, jwks_uri)
        |> Map.put(:token_endpoint_jwt_auth_alg, jwk["alg"])

      parse_registration_params(
        params,
        Map.delete(acc, :jwks_uri)
      )
    else
      _ ->
        parse_registration_params(
          params,
          Map.delete(acc, :jwks_uri)
        )
    end
  end

  defp parse_registration_params(params, %{client_name: name} = acc) do
    parse_registration_params(
      Map.put(params, :name, name),
      Map.delete(acc, :client_name)
    )
  end

  defp parse_registration_params(params, %{token_endpoint_auth_method: method} = acc) do
    parse_registration_params(
      Map.put(params, :token_endpoint_auth_methods, [method]),
      Map.delete(acc, :token_endpoint_auth_method)
    )
  end

  defp parse_registration_params(params, _), do: params
end

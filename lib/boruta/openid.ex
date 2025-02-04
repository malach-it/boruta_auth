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
  alias Boruta.CodesAdapter
  alias Boruta.CredentialsAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.BearerToken
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token
  alias Boruta.Openid.Credential
  alias Boruta.Openid.CredentialResponse
  alias Boruta.Openid.DeferedCredentialResponse
  alias Boruta.Openid.UserinfoResponse
  alias Boruta.VerifiableCredentials
  alias Boruta.VerifiablePresentations

  def jwks(conn, module) do
    jwk_keys = ClientsAdapter.list_clients_jwk()

    module.jwk_list(conn, Enum.map(jwk_keys, &elem(&1, 1)))
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

  def credential(conn, credential_params, default_credential_configuration, module) do
    with {:ok, access_token} <- BearerToken.extract_token(conn),
         {:ok, token} <- AccessToken.authorize(value: access_token),
         {:ok, credential_params} <- validate_credential_params(credential_params),
         {:ok, credential} <-
           VerifiableCredentials.issue_verifiable_credential(
             token.resource_owner,
             credential_params,
             token,
             default_credential_configuration
           ) do
      case credential do
        %{defered: true} ->
          case CredentialsAdapter.create_credential(credential, token) do
            {:ok, credential} ->
              response = DeferedCredentialResponse.from_credential(credential, token)
              module.credential_created(conn, response)

            {:error, error} ->
              error = %Error{
                status: :internal_server_error,
                error: :unknown_error,
                error_description: inspect(error)
              }

              module.credential_failure(conn, error)
          end

        _ ->
          response = CredentialResponse.from_credential(credential, token)
          module.credential_created(conn, response)
      end
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
  end

  def defered_credential(conn, module) do
    with {:ok, access_token} <- BearerToken.extract_token(conn),
         {:ok, token} <- AccessToken.authorize(value: access_token),
         %Credential{} = credential <- CredentialsAdapter.get_by(access_token: token.value) do
      response = CredentialResponse.from_credential(credential, token)
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
  end

  @type direct_post_params :: %{
          code_id: String.t(),
          id_token: nil | String.t(),
          vp_token: nil | String.t(),
          presentation_submission: nil | String.t()
        }
  @spec direct_post(
          conn :: Plug.Conn.t(),
          direct_post_params :: direct_post_params(),
          module :: atom()
        ) :: any()
  def direct_post(conn, direct_post_params, module) do
    with {:ok, _claims} <- check_id_token_client(direct_post_params),
         %Token{value: value} = code <- CodesAdapter.get_by(id: direct_post_params[:code_id]) do
      with {:ok, code} <- Authorization.Code.authorize(%{value: value}),
           :ok <- maybe_check_presentation(direct_post_params, code.presentation_definition),
           {:ok, _code} <- CodesAdapter.revoke(code) do
          query =
            %{
              code: code.value,
              state: code.state
            }
            |> URI.encode_query()

          response = URI.parse(code.redirect_uri)

          response =
            %{response | host: response.host || "", query: query}
            |> URI.to_string()

          module.direct_post_success(conn, response)
      else
        {:error, error} ->
          module.authentication_failure(conn, %{error | redirect_uri: code.redirect_uri, state: code.state})
      end
    else
      {:error, error} ->
        module.authentication_failure(conn, error)

      nil ->
        module.code_not_found(conn)
    end
  end

  defp check_id_token_client(%{id_token: id_token}) do
    case VerifiableCredentials.validate_signature(id_token) do
      {:ok, _jwk, claims} ->
        {:ok, claims}

      {:error, error} ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :unauthorized,
           error_description: error
         }}
    end
  end

  defp check_id_token_client(%{vp_token: vp_token}) do
    case VerifiablePresentations.validate_signature(vp_token) do
      {:ok, _jwk, claims} ->
        {:ok, claims}

      {:error, error} ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :unauthorized,
           error_description: error
         }}
    end
  end

  defp check_id_token_client(_),
    do:
      {:error,
       %Error{
         status: :unauthorized,
         error: :unauthorized,
         error_description: "id_token or vp_token param missing."
       }}

  defp maybe_check_presentation(
         %{vp_token: vp_token, presentation_submission: presentation_submission},
         presentation_definition
       ) do
    case Jason.decode(presentation_submission) do
      {:ok, presentation_submission} ->
        case VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) do
          :ok ->
            :ok

          {:error, error} ->
            error = %Error{
              status: :bad_request,
              format: :query,
              error: :invalid_request,
              error_description: error
            }

            {:error, error}
        end

      {:error, _error} ->
        error = %Error{
          status: :bad_request,
          format: :query,
          error: :invalid_request,
          error_description: "presentation_submission is not a valid JSON object."
        }

        {:error, error}
    end
  end

  defp maybe_check_presentation(
         %{vp_token: _vp_token},
         _presentation_definition
       ) do
    {:error,
     %Error{
       status: :bad_request,
       format: :query,
       error: :invalid_request,
       error_description: "presentation_submission query parameter is missing."
     }}
  end

  defp maybe_check_presentation(_, _), do: :ok

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

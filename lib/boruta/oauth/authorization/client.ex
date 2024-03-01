defmodule Boruta.Oauth.Authorization.Client do
  @moduledoc """
  Check against given params and return the corresponding client
  """

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  alias Boruta.ClientsAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error

  @doc """
  Authorize the client corresponding to the given params.

  ## Examples
      iex> authorize(id: "id", secret: "secret")
      {:ok, %Boruta.Oauth.Client{...}}
  """
  @spec authorize(
          [id: String.t(), source: map(), grant_type: String.t()]
          | [
              id: String.t(),
              source: map() | nil,
              redirect_uri: String.t(),
              grant_type: String.t()
            ]
          | [
              id: String.t(),
              source: map() | nil,
              grant_type: String.t(),
              code_verifier: String.t()
            ]
          | [
              id: String.t(),
              source: map() | nil,
              redirect_uri: String.t(),
              grant_type: String.t(),
              code_verifier: String.t()
            ]
        ) ::
          {:ok, Client.t()}
          | {:error, Error.t()}
  def authorize(id: id, source: source, grant_type: grant_type)
      when not is_nil(id) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         true <- Client.grant_type_supported?(client, grant_type),
         {:ok, client} <- maybe_check_client_secret(client, source, grant_type) do
      {:ok, client}
    else
      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}

      nil ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or client_secret."
         }}

      {:error, reason} ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: reason
         }}
    end
  end

  def authorize(id: id, source: source, redirect_uri: redirect_uri, grant_type: grant_type)
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- Client.check_redirect_uri(client, redirect_uri),
         true <- Client.grant_type_supported?(client, grant_type),
         {:ok, client} <- maybe_check_client_secret(client, source, grant_type) do
      {:ok, client}
    else
      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}

      _ ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or redirect_uri."
         }}
    end
  end

  def authorize(
        id: "did:" <> _key,
        source: source,
        redirect_uri: _redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier
      ) do
    with %Client{} = client <- ClientsAdapter.public!(),
         :ok <- validate_pkce(client, code_verifier),
         true <- Client.grant_type_supported?(client, grant_type),
         {:ok, client} <- maybe_check_client_secret(client, source, grant_type) do
      {:ok, client}
    else
      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}

      {:error, reason} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: to_string(reason)
         }}
    end
  end

  def authorize(
        id: id,
        source: source,
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier
      )
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- Client.check_redirect_uri(client, redirect_uri),
         :ok <- validate_pkce(client, code_verifier),
         true <- Client.grant_type_supported?(client, grant_type),
         {:ok, client} <- maybe_check_client_secret(client, source, grant_type) do
      {:ok, client}
    else
      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}

      {:error, :invalid_pkce_request} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "PKCE request invalid."
         }}

      _ ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or redirect_uri."
         }}
    end
  end

  def authorize(
        id: id,
        source: source,
        grant_type: grant_type,
        code_verifier: code_verifier
      )
      when not is_nil(id) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- validate_pkce(client, code_verifier),
         true <- Client.grant_type_supported?(client, grant_type),
         {:ok, client} <- maybe_check_client_secret(client, source, grant_type) do
      {:ok, client}
    else
      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}

      {:error, :invalid_pkce_request} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "PKCE request invalid."
         }}

      _ ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client."
         }}
    end
  end

  def authorize(_params) do
    {:error,
     %Error{
       status: :unauthorized,
       error: :invalid_client,
       error_description: "Invalid client."
     }}
  end

  defp maybe_check_client_secret(client, source, grant_type) do
    case Client.should_check_secret?(client, grant_type) do
      false ->
        {:ok, client}

      true ->
        with {:ok, secret} <- extract_secret(source, client) do
          case Client.check_secret(client, secret) do
            :ok ->
              {:ok, client}

            {:error, _error} ->
              {:error, "Invalid client_id or client_secret."}
          end
        end
    end
  end

  defp extract_secret(source, client), do: do_extract_secret(source, client, nil)

  defp do_extract_secret(_source, %Client{token_endpoint_auth_methods: []}, message),
    do: {:error, message}

  defp do_extract_secret(
         source,
         %Client{token_endpoint_auth_methods: ["client_secret_basic" | methods]} = client,
         _message
       ) do
    case source[:type] do
      "basic" ->
        {:ok, source[:value]}

      _ ->
        message = "Given client expects the credentials to be provided with BasicAuth."
        do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)
    end
  end

  defp do_extract_secret(
         source,
         %Client{token_endpoint_auth_methods: ["client_secret_post" | methods]} = client,
         _message
       ) do
    case source[:type] do
      "post" ->
        {:ok, source[:value]}

      _ ->
        message = "Given client expects the credentials to be provided with POST body parameters."
        do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)
    end
  end

  defp do_extract_secret(
         source,
         %Client{
           secret: secret,
           token_endpoint_auth_methods: ["client_secret_jwt" | methods],
           token_endpoint_jwt_auth_alg: alg
         } = client,
         _message
       )
       when alg in ["HS256", "HS364", "HS512"] and is_binary(secret) do
    signer = Joken.Signer.create(alg, secret)

    case {source[:type], Token.verify(source[:value] || "", signer)} do
      {"jwt", {:ok, _claims}} ->
        {:ok, secret}

      {"jwt", {:error, _error}} ->
        message = "The given client secret jwt does not match signature key."

        do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)

      {_, _} ->
        message = "Given client expects the credentials to be provided with a jwt assertion."
        do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)
    end
  end

  defp do_extract_secret(
         source,
         %Client{
           jwt_public_key: jwt_public_key,
           token_endpoint_auth_methods: ["private_key_jwt" | _methods],
           token_endpoint_jwt_auth_alg: alg
         } = client,
         _message
       )
       when alg in ["RS256", "RS364", "RS512"] and is_binary(jwt_public_key) do
    signer = Joken.Signer.create(alg, %{"pem" => jwt_public_key})
    verify = Token.verify(source[:value] || "", signer)

    verify_secret_result(client, source, verify, false)
  end

  defp do_extract_secret(source, client, _) do
    do_extract_secret(
      source,
      %{client | token_endpoint_auth_methods: []},
      "Bad client jwt authentication method configuration (jwks and token endpoint jwt auth algorithm do not match)."
    )
  end

  defp verify_secret_result(%Client{secret: secret}, %{type: "jwt"}, {:ok, _claims}, _refreshed?) do
    {:ok, secret}
  end

  defp verify_secret_result(
         %Client{
           id: client_id,
           secret: secret,
           token_endpoint_jwt_auth_alg: alg
         } = client,
         %{type: "jwt"} = source,
         {:error, _reason} = error,
         false
       ) do
    with {:ok, jwt_public_key} <- ClientsAdapter.refresh_jwk_from_jwks_uri(client_id),
         signer <- Joken.Signer.create(alg, %{"pem" => jwt_public_key}),
         {"jwt", {:ok, _claims}} <-
           {source[:type], Token.verify(source[:value] || "", signer)} do
      {:ok, secret}
    else
      _ ->
        verify_secret_result(client, source, error, true)
    end
  end

  defp verify_secret_result(
         %Client{
           token_endpoint_auth_methods: ["private_key_jwt" | methods]
         } = client,
         %{type: "jwt"} = source,
         {:error, _error},
         true
       ) do
    message = "The given client secret jwt does not match signature key."

    do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)
  end

  defp verify_secret_result(
         %Client{
           token_endpoint_auth_methods: ["private_key_jwt" | methods]
         } = client,
         source,
         _error,
         _refreshed
       ) do
    message = "Given client expects the credentials to be provided with a jwt assertion."
    do_extract_secret(source, %{client | token_endpoint_auth_methods: methods}, message)
  end

  defp validate_pkce(%Client{pkce: false}, _code_verifier), do: :ok
  defp validate_pkce(%Client{pkce: true}, ""), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, nil), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, _code_verifier), do: :ok
end

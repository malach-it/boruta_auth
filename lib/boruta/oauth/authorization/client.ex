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
              redirect_uri: String.t(),
              grant_type: String.t(),
              code_verifier: String.t()
            ]
        ) ::
          {:ok, Client.t()}
          | {:error,
             %Error{
               :error => :invalid_client,
               :error_description => String.t(),
               :format => nil,
               :redirect_uri => nil,
               :status => :unauthorized
             }}
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

      _ ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or client_secret."
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
        with {:ok, secret} <- extract_secret(source, client.token_endpoint_auth_methods),
             :ok <- Client.check_secret(client, secret) do
          {:ok, client}
        end
    end
  end

  defp extract_secret(source, methods), do: do_extract_secret(source, methods, nil)

  defp do_extract_secret(_source, [], nil),
    do: {:error, "No client authentication method found for given client."}

  defp do_extract_secret(_source, [], message), do: {:error, message}

  defp do_extract_secret(source, ["client_secret_basic" | methods], _message) do
    case source[:type] do
      "basic" ->
        {:ok, source[:value]}

      _ ->
        message = "Given client expects the credentials to be provided with BasicAuth."
        do_extract_secret(source, methods, message)
    end
  end

  defp do_extract_secret(source, ["client_secret_post" | methods], _message) do
    case source[:type] do
      "post" ->
        {:ok, source[:value]}

      _ ->
        message = "Given client expects the credentials to be provided with POST body parameters."
        do_extract_secret(source, methods, message)
    end
  end

  # defp extract_secret(source, %Client{
  #        secret: secret,
  #        token_endpoint_auth_method: "client_secret_jwt",
  #        token_endpoint_jwt_auth_alg: alg
  #      }) do
  #   signer = Joken.Signer.create(String.to_atom(alg), secret)

  #   case Token.verify(source["value"], signer) do
  #     {:ok, _claims} ->
  #       {:ok, secret}

  #     {:error, _error} ->
  #       {:error, "The given client secret jwt does not match signature key"}
  #   end

  #   {:ok, source["value"]}
  # end

  defp validate_pkce(%Client{pkce: false}, _code_verifier), do: :ok
  defp validate_pkce(%Client{pkce: true}, ""), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, nil), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, _code_verifier), do: :ok
end

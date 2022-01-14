defmodule Boruta.Oauth.Authorization.Client do
  @moduledoc """
  Check against given params and return the corresponding client
  """

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
          [id: String.t(), secret: String.t(), grant_type: String.t()]
          | [id: String.t(), redirect_uri: String.t(), grant_type: String.t()]
          | [
              id: String.t(),
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
  def authorize(id: id, secret: secret, grant_type: grant_type)
      when not is_nil(id) and grant_type in ["revoke", "refresh_token"] do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         true <- Client.grant_type_supported?(client, grant_type) do
      case {apply(Client, :"public_#{grant_type}?", [client]),
            Client.check_secret(client, secret)} do
        {true, _} ->
          {:ok, client}

        {false, :ok} ->
          {:ok, client}

        {false, _} ->
          {:error,
           %Error{
             status: :unauthorized,
             error: :invalid_client,
             error_description: "Invalid client_id or client_secret."
           }}
      end
    else
      nil ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or client_secret."
         }}

      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :unsupported_grant_type,
           error_description: "Client do not support given grant type."
         }}
    end
  end

  def authorize(id: id, secret: secret, grant_type: grant_type)
      when not is_nil(id) and not is_nil(secret) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- Client.check_secret(client, secret),
         true <- Client.grant_type_supported?(client, grant_type) do
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

  def authorize(id: id, redirect_uri: redirect_uri, grant_type: grant_type)
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- Client.check_redirect_uri(client, redirect_uri),
         true <- Client.grant_type_supported?(client, grant_type) do
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
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier
      )
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_client(id),
         :ok <- Client.check_redirect_uri(client, redirect_uri),
         :ok <- validate_pkce(client, code_verifier),
         true <- Client.grant_type_supported?(client, grant_type) do
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

  defp validate_pkce(%Client{pkce: false}, _code_verifier), do: :ok
  defp validate_pkce(%Client{pkce: true}, ""), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, nil), do: {:error, :invalid_pkce_request}
  defp validate_pkce(%Client{pkce: true}, _code_verifier), do: :ok
end

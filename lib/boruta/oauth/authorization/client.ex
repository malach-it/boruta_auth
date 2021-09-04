defmodule Boruta.Oauth.Authorization.Client do
  @moduledoc """
  Client authorization
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
          [id: String.t(), secret: String.t()]
          | [id: String.t(), secret: String.t(), grant_type: String.t()]
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
  def authorize(id: id, secret: secret) when not is_nil(id) and not is_nil(secret) do
    case ClientsAdapter.get_by(id: id, secret: secret) do
      %Client{} = client ->
        {:ok, client}

      nil ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or client_secret."
         }}
    end
  end

  def authorize(id: id, secret: secret, grant_type: "refresh_token")
      when not is_nil(id) do
    with %Client{} = client <- ClientsAdapter.get_by(id: id),
         true <- Client.grant_type_supported?(client, "refresh_token") do
      case {Client.public_refresh_token?(client), Client.check_secret(client, secret)} do
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
    with %Client{} = client <-
           ClientsAdapter.get_by(id: id, secret: secret),
         true <- Client.grant_type_supported?(client, grant_type) do
      {:ok, client}
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

  def authorize(id: id, redirect_uri: redirect_uri, grant_type: grant_type)
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_by(id: id, redirect_uri: redirect_uri),
         true <- Client.grant_type_supported?(client, grant_type) do
      {:ok, client}
    else
      nil ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or redirect_uri."
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

  def authorize(
        id: id,
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier
      )
      when not is_nil(id) and not is_nil(redirect_uri) do
    with %Client{} = client <- ClientsAdapter.get_by(id: id, redirect_uri: redirect_uri),
         :ok <- validate_pkce(client, code_verifier),
         true <- Client.grant_type_supported?(client, grant_type) do
      {:ok, client}
    else
      nil ->
        {:error,
         %Error{
           status: :unauthorized,
           error: :invalid_client,
           error_description: "Invalid client_id or redirect_uri."
         }}

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

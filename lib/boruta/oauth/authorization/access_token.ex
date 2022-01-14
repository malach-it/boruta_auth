defmodule Boruta.Oauth.Authorization.AccessToken do
  @moduledoc """
  Check against given params and return the corresponding access token
  """

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token

  @doc """
  Authorize the access token corresponding to the given params.

  ## Examples
      iex> authorize(%{value: "value"})
      {:ok, %Boruta.Oauth.Token{...}}
  """
  @spec authorize(
          params ::
            [value: String.t()]
            | [refresh_token: String.t()]
        ) ::
          {:error,
           %Error{
             :error => :invalid_access_token,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :unauthorized
           }}
          | {:ok, %Token{}}
  def authorize(value: value) do
    with %Token{} = token <- Boruta.AccessTokensAdapter.get_by(value: value),
         :ok <- Token.ensure_valid(token) do
      {:ok, token}
    else
      {:error, :token_revoked} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given access token is invalid."
         }}

      {:error, error} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_access_token,
           error_description: error
         }}

      nil ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_access_token,
           error_description: "Provided access token is invalid."
         }}
    end
  end

  def authorize(refresh_token: refresh_token) do
    with %Token{} = token <- Boruta.AccessTokensAdapter.get_by(refresh_token: refresh_token),
      :ok <- Token.ensure_valid(token, :refresh_token) do
      {:ok, token}
    else
      {:error, "Token revoked."} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given refresh token is invalid."
         }}

      {:error, error} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_refresh_token,
           error_description: error
         }}

      nil ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_refresh_token,
           error_description: "Provided refresh token is incorrect."
         }}
    end
  end
end

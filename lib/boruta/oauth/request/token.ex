defmodule Boruta.Oauth.Request.Token do
  @moduledoc false

  import Boruta.Oauth.Request.Base

  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.Validator

  @spec request(conn :: Plug.Conn.t() | map()) ::
          {:error,
           %Error{
             :error => :invalid_request,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok,
             oauth_request ::
               AuthorizationCodeRequest.t()
               | ClientCredentialsRequest.t()
               | PasswordRequest.t()}
  def request(%{body_params: body_params} = request) do
    with {:ok, unsigned_params} <- fetch_unsigned_request(request),
         {:ok, client_authentication_params} <- fetch_client_authentication(request),
         {:ok, dpop} <- fetch_dpop(request),
         {:ok, params} <-
           Validator.validate(
             :token,
             body_params
             |> Map.put("dpop", %{dpop: dpop, request: request})
             |> Enum.into(unsigned_params)
             |> Enum.into(client_authentication_params)
           ) do
      build_request(params)
    else
      {:error, error_description} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: error_description
         }}
    end
  end

  defp fetch_dpop(%{req_headers: req_headers}) do
    with {"dpop", dpop} <- List.keyfind(req_headers, "dpop", 0),
         nil <- List.keyfind(req_headers, "dpop", 1) do
      {:ok, dpop}
    else
      {"dpop", _dpop} ->
        {:error, "More than one DPoP header present in the request."}

      _ ->
        {:ok, nil}
    end
  end
end

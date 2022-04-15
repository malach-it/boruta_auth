defmodule Boruta.Oauth.BearerToken do
  @moduledoc """
  OAuth bearer token utilities

  Provide utilities to manipulate bearer tokens as stated in [RFC 6750 - Bearer token usage](https://datatracker.ietf.org/doc/html/rfc6750)
  """

  alias Boruta.Oauth.Error

  @spec extract_token(conn :: Plug.Conn.t()) ::
          {:ok, access_token :: String.t()} | {:error, error :: Error.t()}
  def extract_token(%Plug.Conn{body_params: %{"access_token" => access_token}}) do
    case access_token do
      access_token when is_binary(access_token) ->
        {:ok, access_token}

      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Invalid bearer from body params."
         }}
    end
  end

  def extract_token(%Plug.Conn{} = conn) do
    with [authorization_header] <- Plug.Conn.get_req_header(conn, "authorization"),
         [_authorization_header, access_token] <- Regex.run(~r/Bearer (.+)/, authorization_header) do
      {:ok, access_token}
    else
      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Invalid bearer from Authorization header."
         }}
    end
  end
end

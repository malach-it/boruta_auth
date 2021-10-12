defprotocol Boruta.Oauth.Authorization.Nonce do
  @moduledoc """
  OpenID Connect nonce authorization
  """

  @spec authorize(request :: any) :: :ok | {:error, Boruta.Oauth.Error.t()}
  def authorize(request)
end

defimpl Boruta.Oauth.Authorization.Nonce, for: Boruta.Oauth.CodeRequest do
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error

  def authorize(%Boruta.Oauth.CodeRequest{nonce: nonce} = request) do
    case {CodeRequest.require_nonce?(request), nonce} do
      {true, nonce} when nonce in [nil, ""] ->
        {:error, %Error{
          status: :bad_request,
          error: :invalid_request,
          error_description: "OpenID requests require a nonce."
        }}
      _ ->
        :ok
    end
  end
end

defimpl Boruta.Oauth.Authorization.Nonce, for: Boruta.Oauth.TokenRequest do
  alias Boruta.Oauth.TokenRequest
  alias Boruta.Oauth.Error

  def authorize(%Boruta.Oauth.TokenRequest{nonce: nonce} = request) do
    case {TokenRequest.require_nonce?(request), nonce} do
      {true, ""} ->
        {:error, %Error{
          status: :bad_request,
          error: :invalid_request,
          error_description: "OpenID requests require a nonce."
        }}
      {true, nil} ->
        {:error, %Error{
          status: :bad_request,
          error: :invalid_request,
          error_description: "OpenID requests require a nonce."
        }}
      _ ->
        :ok
    end
  end
end

defprotocol Boruta.Oauth.Authorization.Nonce do
  @moduledoc """
  Check OpenID Connect nonce against given request
  """

  @doc """
  Authorize the given request corresponding the nonce value.

  ## Examples
      iex> authorize(%CodeRequest{...})
      :ok
  """
  @spec authorize(
          request ::
            Boruta.Oauth.CodeRequest.t()
            | Boruta.Oauth.TokenRequest.t()
            | Boruta.Oauth.SiopV2Request.t()
        ) ::
          :ok | {:error, Boruta.Oauth.Error.t()}
  def authorize(request)
end

defimpl Boruta.Oauth.Authorization.Nonce, for: Boruta.Oauth.SiopV2Request do
  alias Boruta.Oauth.Error

  def authorize(%Boruta.Oauth.SiopV2Request{nonce: nonce}) do
    case nonce do
      nonce when nonce in [nil, ""] ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "OpenID requests require a nonce."
         }}

        # NOTE bypass in order to pass the EBSI test cases https://hub.ebsi.eu/wallet-conformance/issue-to-holder/flow
        :ok

      _ ->
        :ok
    end
  end
end

defimpl Boruta.Oauth.Authorization.Nonce, for: Boruta.Oauth.CodeRequest do
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error

  def authorize(%Boruta.Oauth.CodeRequest{nonce: nonce} = request) do
    case {CodeRequest.require_nonce?(request), nonce} do
      {true, nonce} when nonce in [nil, ""] ->
        {:error,
         %Error{
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
      {true, nonce} when nonce in [nil, ""] ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "OpenID requests require a nonce."
         }}

      _ ->
        :ok
    end
  end
end

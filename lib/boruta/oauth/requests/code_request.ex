defmodule Boruta.Oauth.CodeRequest do
  @moduledoc """
  Code request
  """

  @typedoc """
  Type representing a code request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.1.1).

  Note : `resource_owner` is an addition that must be provided by the application layer.
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          state: String.t(),
          nonce: String.t(),
          scope: String.t(),
          resource_owner: struct(),
          grant_type: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          response_types: String.t()
        }

  defstruct client_id: "",
            redirect_uri: "",
            state: "",
            nonce: "",
            scope: "",
            resource_owner: nil,
            grant_type: "authorization_code",
            code_challenge: "",
            code_challenge_method: "plain",
            response_types: []

  alias Boruta.Oauth.Scope

  @spec require_nonce?(request :: __MODULE__.t()) :: boolean()
  def require_nonce?(%__MODULE__{response_types: response_types} = request) do
    openid?(request) && Enum.member?(response_types, "id_token")
  end

  defp openid?(%__MODULE__{scope: scope}) when is_binary(scope) do
    String.match?(scope, ~r/#{Scope.openid().name}/)
  end
  defp openid?(_request), do: false
end

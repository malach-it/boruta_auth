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

  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct client_id: nil,
            redirect_uri: nil,
            state: "",
            nonce: "",
            scope: "",
            resource_owner: nil,
            response_type: "code",
            grant_type: "authorization_code",
            code_challenge: "",
            code_challenge_method: "plain",
            response_types: []

  alias Boruta.Oauth.Scope

  @spec require_nonce?(request :: __MODULE__.t()) :: boolean()
  def require_nonce?(%__MODULE__{response_types: response_types, scope: scope}) do
    Scope.contains_openid?(scope) && Enum.member?(response_types, "id_token")
  end
end
